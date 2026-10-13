import { errAsync, okAsync } from 'neverthrow'
import {
  defineProviderId,
  parseEmail,
  ProviderError,
  type CookieOptions,
  type IdentityProviderPort,
  type LoggerPort,
} from '@payload-auth-link/core'
import type { Payload, PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { createEndpoints } from '../endpoints.js'
import { wireOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

function clearProvider(
  id: string,
  names: readonly string[],
  clear?: (name: string) => CookieOptions | undefined
): IdentityProviderPort {
  return {
    id: defineProviderId(id),
    capabilities: new Set(),
    sessionCookieNames: names,
    ...(clear === undefined ? {} : { sessionCookieClearOptions: clear }),
    getSession: () => okAsync(null),
    revokeSession: () => okAsync(undefined),
  }
}

async function logoutCookies(
  providers: readonly IdentityProviderPort[]
): Promise<readonly string[]> {
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['user'],
    defaultRole: 'user',
    providers,
  })
  const endpoint = createEndpoints(wired).find(
    (candidate) => candidate.path === '/auth-link/session' && candidate.method === 'delete'
  )
  if (!endpoint?.handler) {
    throw new Error('logout endpoint missing')
  }
  const request = {
    headers: new Headers({ 'x-auth-link-csrf': '1' }),
    payload: {},
  } as unknown as PayloadRequest
  const response = await endpoint.handler(request)
  return response.headers.getSetCookie()
}

describe('logout cookie clearing', () => {
  it('clears plain cookies without Secure', async () => {
    const cookies = await logoutCookies([clearProvider('plain', ['al_session'], () => ({}))])
    expect(cookies).toEqual(['al_session=; Max-Age=0; Path=/'])
  })

  it('carries Secure and Domain from provider-reported attributes', async () => {
    const cookies = await logoutCookies([
      clearProvider('secure', ['acme.session'], () => ({
        secure: true,
        domain: 'example.com',
      })),
    ])
    expect(cookies).toEqual(['acme.session=; Max-Age=0; Domain=example.com; Path=/; Secure'])
  })

  it('derives Secure from the __Secure- prefix when the provider predates the hook', async () => {
    const cookies = await logoutCookies([clearProvider('legacy', ['__Secure-al_session'])])
    expect(cookies).toEqual(['__Secure-al_session=; Max-Age=0; Path=/; Secure'])
  })

  it('also expires non-session logout cookies like BA admin_session (CAP-8a)', async () => {
    const provider: IdentityProviderPort = {
      ...clearProvider('ba-like', ['better-auth.session_token'], () => ({})),
      logoutCookieNames: ['better-auth.admin_session', 'better-auth.session_token'],
    }
    const cookies = await logoutCookies([provider])
    // Deduped: the token appears in both lists but is expired once.
    expect(cookies).toEqual([
      'better-auth.session_token=; Max-Age=0; Path=/',
      'better-auth.admin_session=; Max-Age=0; Path=/',
    ])
  })
})

function capturingLogger(): {
  logger: LoggerPort
  warn: ReturnType<typeof vi.fn>
  error: ReturnType<typeof vi.fn>
} {
  const warn = vi.fn()
  const error = vi.fn()
  const logger: LoggerPort = {
    debug: vi.fn(),
    info: vi.fn(),
    warn,
    error,
    child: () => logger,
  }
  return { logger, warn, error }
}

function stubPayload(overrides: {
  find?: (args: unknown) => Promise<unknown>
  findByID?: (args: unknown) => Promise<unknown>
}): Payload {
  return {
    find: overrides.find ?? (() => Promise.resolve({ docs: [] })),
    findByID: overrides.findByID ?? (() => Promise.resolve(null)),
  } as unknown as Payload
}

const linkedDoc = {
  id: 'user-1',
  email: 'linked@test.dev',
  roles: ['user'],
  identities: [
    {
      providerId: 'stub',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      linkedAt: new Date().toISOString(),
    },
  ],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
}

function failingProvider(id: string): IdentityProviderPort {
  const providerId = defineProviderId(id)
  return {
    id: providerId,
    capabilities: new Set(),
    sessionCookieNames: [`al_${id}_session`],
    getSession: () => errAsync(new ProviderError(providerId, 'getSession')),
    revokeSession: () => okAsync(undefined),
  }
}

function sessionHandler(
  method: 'get' | 'delete',
  logger: LoggerPort,
  ...providers: IdentityProviderPort[]
): (request: PayloadRequest) => Response | Promise<Response> {
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['user'],
    defaultRole: 'user',
    providers,
    logger,
  })
  const endpoint = createEndpoints(wired).find(
    (candidate) => candidate.path === '/auth-link/session' && candidate.method === method
  )
  if (!endpoint?.handler) {
    throw new Error('session endpoint missing')
  }
  return endpoint.handler
}

describe('guest session endpoint (CAP-10)', () => {
  it('answers 200 with a guest principal and no user for anonymous sessions', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'guest-1',
      providerUserId: 'anon-1',
      email: 'temp-1@anonymous.placeholder.invalid',
      expiresAt: new Date(Date.now() + 3600_000),
      anonymous: true,
    })
    const handler = sessionHandler('get', capturingLogger().logger, stub.provider)
    const response = await handler({
      headers: new Headers({ cookie }),
      payload: stubPayload({}),
    } as unknown as PayloadRequest)
    expect(response.status).toBe(200)
    const body = (await response.json()) as {
      user: unknown
      guest?: { id: string; providerId: string }
    }
    expect(body.user).toBeNull()
    expect(body.guest).toMatchObject({ id: 'anon-1', providerId: 'stub' })
  })
})

describe('session verify logging', () => {
  it('warns on invalid sessions before the GET 401', async () => {
    const logs = capturingLogger()
    const { provider } = createStubProvider()
    const handler = sessionHandler('get', logs.logger, provider)
    const denied = await handler({
      headers: new Headers(),
      payload: stubPayload({}),
    } as unknown as PayloadRequest)
    expect(denied.status).toBe(401)
    expect(logs.warn).toHaveBeenCalledWith('session endpoint verification failed: invalid session')
    expect(logs.error).not.toHaveBeenCalled()
  })

  it('returns 401 when every provider fails its session read', async () => {
    const logs = capturingLogger()
    const handler = sessionHandler(
      'get',
      logs.logger,
      failingProvider('first'),
      failingProvider('second')
    )
    const denied = await handler({
      headers: new Headers(),
      payload: stubPayload({}),
    } as unknown as PayloadRequest)
    expect(denied.status).toBe(401)
    expect(logs.warn).toHaveBeenCalledWith('session endpoint verification failed: invalid session')
    expect(logs.error).not.toHaveBeenCalled()
  })

  it('errors with cause on storage outages before the GET 401', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'live-1',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const logs = capturingLogger()
    const handler = sessionHandler('get', logs.logger, stub.provider)
    const failure = new Error('db down')
    const denied = await handler({
      headers: new Headers({ cookie }),
      payload: stubPayload({ find: () => Promise.reject(failure) }),
    } as unknown as PayloadRequest)
    expect(denied.status).toBe(401)
    expect(logs.error).toHaveBeenCalledWith('session endpoint verification failed: storage error', {
      cause: failure,
    })
  })

  it("serializes 'unknown' assurance and omits unknown actor/tenant on GET (PORT-4)", async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'live-port4',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const handler = sessionHandler('get', capturingLogger().logger, stub.provider)
    const ok = await handler({
      headers: new Headers({ cookie }),
      payload: stubPayload({
        find: () => Promise.resolve({ docs: [linkedDoc] }),
        findByID: () => Promise.resolve(linkedDoc),
      }),
    } as unknown as PayloadRequest)
    expect(ok.status).toBe(200)
    const body: unknown = await ok.json()
    expect(body).toEqual({
      user: {
        id: 'user-1',
        collection: 'users',
        email: 'linked@test.dev',
        roles: ['user'],
        // The stub provider cannot tell how the session was proven:
        // that fact serializes as 'unknown', it is not dropped.
        assurance: { methods: 'unknown', mfa: 'unknown' },
      },
    })
  })

  it('errors on user reload outages and warns on missing docs', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'live-2',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const headers = new Headers({ cookie })
    const logs = capturingLogger()
    const handler = sessionHandler('get', logs.logger, stub.provider)
    // Verify succeeds off the linked doc; the reload then fails.
    const failure = new Error('db down')
    const reloaded = await handler({
      headers,
      payload: stubPayload({
        find: () => Promise.resolve({ docs: [linkedDoc] }),
        findByID: () => Promise.reject(failure),
      }),
    } as unknown as PayloadRequest)
    expect(reloaded.status).toBe(401)
    expect(logs.error).toHaveBeenCalledWith('session endpoint user reload failed', {
      cause: failure,
    })
    const missing = await handler({
      headers,
      payload: stubPayload({
        find: () => Promise.resolve({ docs: [linkedDoc] }),
        findByID: () => Promise.resolve(null),
      }),
    } as unknown as PayloadRequest)
    expect(missing.status).toBe(401)
    expect(logs.warn).toHaveBeenCalledWith('session endpoint session has no user document')
  })

  it('warns on idempotent logout and errors on logout storage outages', async () => {
    const logs = capturingLogger()
    const stub = createStubProvider()
    const handler = sessionHandler('delete', logs.logger, stub.provider)
    const csrf = { 'x-auth-link-csrf': '1' }
    const alreadyOut = await handler({
      headers: new Headers(csrf),
      payload: stubPayload({}),
    } as unknown as PayloadRequest)
    expect(alreadyOut.status).toBe(401)
    expect(alreadyOut.headers.getSetCookie().length).toBeGreaterThan(0)
    expect(logs.warn).toHaveBeenCalledWith('logout endpoint verification failed: invalid session')

    const cookie = stub.issue({
      sessionId: 'live-3',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const failure = new Error('db down')
    const broken = await handler({
      headers: new Headers({ ...csrf, cookie }),
      payload: stubPayload({ find: () => Promise.reject(failure) }),
    } as unknown as PayloadRequest)
    expect(broken.status).toBe(401)
    expect(logs.error).toHaveBeenCalledWith('logout endpoint verification failed: storage error', {
      cause: failure,
    })
  })
})

/**
 * Provider presenting one fixed live session, recording every revoke.
 * Its cookie is `__Secure-` with a custom Domain so clearing must carry
 * the live attributes.
 */
function presentingProvider(
  id: string,
  revoked: string[],
  options: { failRevoke?: boolean } = {}
): IdentityProviderPort {
  const providerId = defineProviderId(id)
  return {
    id: providerId,
    capabilities: new Set(),
    sessionCookieNames: [`__Secure-${id}.session`],
    sessionCookieClearOptions: () => ({ secure: true, domain: 'example.com' }),
    getSession: () => {
      const email = parseEmail('second@test.dev')
      if (email.isErr()) {
        throw email.error
      }
      return okAsync({
        sessionId: `${id}-session`,
        providerUserId: `${id}-1`,
        email: email.value,
        emailVerified: true,
        expiresAt: new Date(Date.now() + 3600_000),
        identity: {
          email: { value: email.value, verified: true },
          phone: null,
          anonymous: false,
        },
        assurance: { methods: 'unknown' as const, mfa: 'unknown' as const },
        actor: null,
        organizationId: null,
        channel: 'cookie' as const,
      })
    },
    revokeSession: (sessionId) => {
      if (options.failRevoke === true) {
        return errAsync(new ProviderError(providerId, 'revokeSession'))
      }
      revoked.push(sessionId)
      return okAsync(undefined)
    },
  }
}

describe('multi-provider logout', () => {
  const csrf = { 'x-auth-link-csrf': '1' }
  const expectedClears = [
    'al_stub_session=; Max-Age=0; Path=/',
    '__Secure-second.session=; Max-Age=0; Domain=example.com; Path=/; Secure',
  ]

  function signedInStub(): { stub: ReturnType<typeof createStubProvider>; cookie: string } {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'live-multi',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    return { stub, cookie }
  }

  it('revokes every presenting provider and clears every cookie on 200', async () => {
    const revoked: string[] = []
    const { stub, cookie } = signedInStub()
    const handler = sessionHandler(
      'delete',
      capturingLogger().logger,
      stub.provider,
      presentingProvider('second', revoked)
    )
    const signedOut = await handler({
      headers: new Headers({ ...csrf, cookie }),
      payload: stubPayload({ find: () => Promise.resolve({ docs: [linkedDoc] }) }),
    } as unknown as PayloadRequest)
    expect(signedOut.status).toBe(200)
    // The verified (first-registered) provider's session is revoked by
    // the session service; the second one by the logout sweep.
    expect(stub.sessions.has('live-multi')).toBe(false)
    expect(revoked).toEqual(['second-session'])
    expect(signedOut.headers.getSetCookie()).toEqual(expectedClears)
  })

  it('sweeps live provider sessions and clears every cookie on the idempotent 401', async () => {
    const revoked: string[] = []
    const stub = createStubProvider()
    const handler = sessionHandler(
      'delete',
      capturingLogger().logger,
      stub.provider,
      presentingProvider('second', revoked)
    )
    // The second provider's session resolves to no linkable user (no
    // docs, no create): verify fails, but its session must still die.
    const alreadyOut = await handler({
      headers: new Headers(csrf),
      payload: stubPayload({
        find: () => Promise.reject(new Error('db down')),
      }),
    } as unknown as PayloadRequest)
    expect(alreadyOut.status).toBe(401)
    expect(revoked).toEqual(['second-session'])
    expect(alreadyOut.headers.getSetCookie()).toEqual(expectedClears)
  })

  it('revokes additional same-provider sessions and expires presented multi cookies (CAP-13b)', async () => {
    const { stub, cookie } = signedInStub()
    const revoked: string[] = []
    const multiProvider: IdentityProviderPort = {
      ...stub.provider,
      revokeSession: (sessionId) => {
        revoked.push(sessionId)
        return stub.provider.revokeSession(sessionId)
      },
      listPresentedSessionIds: () => okAsync(['live-multi', 'sibling-session', '']),
      presentedLogoutCookieNames: () => ['al_stub_session_multi-sibling-session'],
    }
    const handler = sessionHandler('delete', capturingLogger().logger, multiProvider)
    const signedOut = await handler({
      headers: new Headers({ ...csrf, cookie }),
      payload: stubPayload({ find: () => Promise.resolve({ docs: [linkedDoc] }) }),
    } as unknown as PayloadRequest)
    expect(signedOut.status).toBe(200)
    // Active session once via the session service; sibling via the sweep.
    expect(revoked).toEqual(['live-multi', 'sibling-session'])
    const cleared = signedOut.headers.getSetCookie().map((entry) => entry.split('=', 1)[0])
    expect(cleared).toContain('al_stub_session_multi-sibling-session')
  })

  it('logs a failing multi-session enumeration without failing the logout (CAP-13b)', async () => {
    const logs = capturingLogger()
    const { stub, cookie } = signedInStub()
    const multiProvider: IdentityProviderPort = {
      ...stub.provider,
      listPresentedSessionIds: () =>
        errAsync(new ProviderError(defineProviderId('stub'), 'listPresentedSessionIds')),
    }
    const handler = sessionHandler('delete', logs.logger, multiProvider)
    const signedOut = await handler({
      headers: new Headers({ ...csrf, cookie }),
      payload: stubPayload({ find: () => Promise.resolve({ docs: [linkedDoc] }) }),
    } as unknown as PayloadRequest)
    expect(signedOut.status).toBe(200)
    expect(logs.warn).toHaveBeenCalledWith('logout multi-session enumeration failed', {
      providerId: 'stub',
    })
  })

  it('logs a failing sibling revoke without failing the logout (CAP-13b)', async () => {
    const logs = capturingLogger()
    const { stub, cookie } = signedInStub()
    const multiProvider: IdentityProviderPort = {
      ...stub.provider,
      revokeSession: (sessionId) =>
        sessionId === 'sibling-session'
          ? errAsync(new ProviderError(defineProviderId('stub'), 'revokeSession'))
          : stub.provider.revokeSession(sessionId),
      listPresentedSessionIds: () => okAsync(['sibling-session']),
    }
    const handler = sessionHandler('delete', logs.logger, multiProvider)
    const signedOut = await handler({
      headers: new Headers({ ...csrf, cookie }),
      payload: stubPayload({ find: () => Promise.resolve({ docs: [linkedDoc] }) }),
    } as unknown as PayloadRequest)
    expect(signedOut.status).toBe(200)
    expect(logs.error).toHaveBeenCalledWith(
      'logout multi-session revoke failed',
      expect.objectContaining({ providerId: 'stub' })
    )
  })

  it('logs a failing sweep revoke without failing the logout', async () => {
    const logs = capturingLogger()
    const { stub, cookie } = signedInStub()
    const handler = sessionHandler(
      'delete',
      logs.logger,
      stub.provider,
      presentingProvider('second', [], { failRevoke: true }),
      failingProvider('third')
    )
    const signedOut = await handler({
      headers: new Headers({ ...csrf, cookie }),
      payload: stubPayload({ find: () => Promise.resolve({ docs: [linkedDoc] }) }),
    } as unknown as PayloadRequest)
    expect(signedOut.status).toBe(200)
    expect(logs.error).toHaveBeenCalledWith(
      'logout provider session revoke failed',
      expect.objectContaining({ providerId: 'second' })
    )
    expect(logs.warn).toHaveBeenCalledWith('logout provider session read failed', {
      providerId: 'third',
    })
    expect(signedOut.headers.getSetCookie()).toHaveLength(3)
  })
})
