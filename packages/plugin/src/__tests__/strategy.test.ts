import { nullLogger, type LoggerPort } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { createAuthLinkStrategy } from '../strategy.js'
import { wireOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

function capturingLogger(): {
  logger: LoggerPort
  debug: ReturnType<typeof vi.fn>
  warn: ReturnType<typeof vi.fn>
  error: ReturnType<typeof vi.fn>
} {
  const debug = vi.fn()
  const warn = vi.fn()
  const error = vi.fn()
  const logger: LoggerPort = {
    debug,
    info: vi.fn(),
    warn,
    error,
    child: () => logger,
  }
  return { logger, debug, warn, error }
}

function stubPayload(overrides: {
  find?: (args: unknown) => Promise<unknown>
  findByID?: (args: unknown) => Promise<unknown>
  defaultIDType?: 'number' | 'text'
}): Payload {
  return {
    db: { defaultIDType: overrides.defaultIDType ?? 'text' },
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

async function authenticate(
  logger: LoggerPort,
  provider: ReturnType<typeof createStubProvider>['provider'],
  headers: Headers,
  payload: Payload
): Promise<{ user: unknown }> {
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [provider],
    logger,
  })
  const strategy = createAuthLinkStrategy(wired)
  return strategy.authenticate({ headers, payload })
}

async function authenticateWired(
  wired: Parameters<typeof createAuthLinkStrategy>[0],
  headers: Headers,
  payload: Payload
): Promise<{ user: unknown }> {
  const strategy = createAuthLinkStrategy(wired)
  return strategy.authenticate({ headers, payload })
}

describe('strategy verify logging', () => {
  it('warns and returns null for an invalid session', async () => {
    const logs = capturingLogger()
    const { provider } = createStubProvider()
    const result = await authenticate(logs.logger, provider, new Headers(), stubPayload({}))
    expect(result).toEqual({ user: null })
    // Anonymous traffic: debug-level residue, not a warning (issue #15).
    expect(logs.debug).toHaveBeenCalledWith('strategy verification failed: invalid session')
    expect(logs.warn).not.toHaveBeenCalled()
    expect(logs.error).not.toHaveBeenCalled()
  })

  it('warns and returns null for an expired session', async () => {
    const logs = capturingLogger()
    const { provider, issue } = createStubProvider()
    const cookie = issue({
      sessionId: 'expired-1',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() - 1000),
    })
    const result = await authenticate(
      logs.logger,
      provider,
      new Headers({ cookie }),
      stubPayload({})
    )
    expect(result).toEqual({ user: null })
    expect(logs.warn).toHaveBeenCalledWith('strategy verification failed: session expired')
    expect(logs.error).not.toHaveBeenCalled()
  })

  it('errors with cause and returns null on a storage outage', async () => {
    const logs = capturingLogger()
    const { provider, issue } = createStubProvider()
    const cookie = issue({
      sessionId: 'live-1',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const failure = new Error('db down')
    const result = await authenticate(
      logs.logger,
      provider,
      new Headers({ cookie }),
      stubPayload({ find: () => Promise.reject(failure) })
    )
    expect(result).toEqual({ user: null })
    expect(logs.error).toHaveBeenCalledWith('strategy verification failed: storage error', {
      cause: failure,
    })
  })

  it('errors with cause when the user reload fails', async () => {
    const logs = capturingLogger()
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'live-3',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const failure = new Error('db down')
    const result = await authenticate(
      logs.logger,
      stub.provider,
      new Headers({ cookie }),
      stubPayload({
        find: () => Promise.resolve({ docs: [linkedDoc] }),
        findByID: () => Promise.reject(failure),
      })
    )
    expect(result).toEqual({ user: null })
    expect(logs.error).toHaveBeenCalledWith('strategy user reload failed', { cause: failure })
  })

  it('warns when the session has no user document', async () => {
    const logs = capturingLogger()
    const { provider, issue } = createStubProvider()
    const cookie = issue({
      sessionId: 'live-2',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const result = await authenticate(
      logs.logger,
      provider,
      new Headers({ cookie }),
      stubPayload({
        find: () => Promise.resolve({ docs: [linkedDoc] }),
        findByID: () => Promise.resolve(null),
      })
    )
    expect(result).toEqual({ user: null })
    expect(logs.warn).toHaveBeenCalledWith('strategy session has no user document')
    expect(logs.error).not.toHaveBeenCalled()
  })
})

describe('role projection (issue #56)', () => {
  it('projects stored role values when projectRolesAs is stored, after the MFA gate', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'proj-1',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const headers = new Headers({ cookie })
    const payload = stubPayload({
      find: () =>
        Promise.resolve({
          docs: [
            {
              ...linkedDoc,
              roles: ['frontPlugin'],
            },
          ],
          totalDocs: 1,
        }),
      findByID: () =>
        Promise.resolve({
          ...linkedDoc,
          roles: ['frontPlugin'],
        }),
    })
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'front-plugin'],
      defaultRole: 'user',
      roleManagerRoles: ['user'],
      providers: [stub.provider],
      roleValues: { 'front-plugin': 'frontPlugin' },
      projectRolesAs: 'stored',
      logger: nullLogger(),
    })
    const result = await authenticateWired(wired, headers, payload)
    const user = result.user as { roles?: string[] } | null
    // The STORED form reaches req.user; access checks comparing the
    // stored literal keep working unchanged.
    expect(user?.roles).toEqual(['frontPlugin'])
  })

  it('drops (never passes through raw) a role the stored projection cannot map', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'proj-unmapped',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const doc = { ...linkedDoc, roles: ['frontPlugin', 'user'] }
    const payload = stubPayload({
      find: () => Promise.resolve({ docs: [doc], totalDocs: 1 }),
      findByID: () => Promise.resolve(doc),
    })
    const { logger, warn } = capturingLogger()
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'front-plugin'],
      defaultRole: 'user',
      roleManagerRoles: ['user'],
      providers: [stub.provider],
      roleValues: { 'front-plugin': 'frontPlugin' },
      projectRolesAs: 'stored',
      logger,
    })
    // A drifted wiring: the map lost its entry for `front-plugin`.
    const drifted = { ...wired, roleValues: { user: 'user' } }
    const result = await authenticateWired(drifted, new Headers({ cookie }), payload)
    expect((result.user as { roles?: string[] } | null)?.roles).toEqual(['user'])
    expect(warn).toHaveBeenCalledWith('strategy dropped a role with no stored value', {
      role: 'front-plugin',
    })
  })

  it('keeps the MFA-gated roles canonical in the default projection', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'proj-2',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const headers = new Headers({ cookie })
    const payload = stubPayload({
      find: () =>
        Promise.resolve({
          docs: [
            {
              ...linkedDoc,
              roles: ['frontPlugin', 'user'],
            },
          ],
          totalDocs: 1,
        }),
      findByID: () =>
        Promise.resolve({
          ...linkedDoc,
          roles: ['frontPlugin', 'user'],
        }),
    })
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'front-plugin'],
      defaultRole: 'user',
      roleManagerRoles: ['user'],
      providers: [stub.provider],
      roleValues: { 'front-plugin': 'frontPlugin' },
      logger: nullLogger(),
    })
    const result = await authenticateWired(wired, headers, payload)
    const user = result.user as { roles?: string[] } | null
    expect(user?.roles).toEqual(['front-plugin', 'user'])
  })
})

describe('reqUser: document (issue #57)', () => {
  it('loads the full document with projected fields on top', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'doc-1',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const payload = stubPayload({
      find: () =>
        Promise.resolve({
          docs: [{ ...linkedDoc, activeOrganization: 'org-7', department: null }],
          totalDocs: 1,
        }),
      findByID: () =>
        Promise.resolve({
          ...linkedDoc,
          activeOrganization: 'org-7',
          department: null,
        }),
    })
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user'],
      defaultRole: 'user',
      roleManagerRoles: ['user'],
      reqUser: 'document',
      providers: [stub.provider],
      logger: nullLogger(),
    })
    const result = await authenticateWired(wired, new Headers({ cookie }), payload)
    const user = result.user as Record<string, unknown> | null
    expect(user?.activeOrganization).toBe('org-7')
    expect(user?.department).toBeNull()
    expect(user?.roles).toEqual(['user'])
    expect(user?.collection).toBe('users')
    expect(user?._strategy).toBe('auth-link')
  })

  it('falls back to the projection when the document read returns no record', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'doc-gone',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    let reads = 0
    const payload = stubPayload({
      find: () => Promise.resolve({ docs: [linkedDoc], totalDocs: 1 }),
      // The repository's reload sees the user; the document load (a
      // second read, e.g. after a concurrent delete) does not.
      findByID: () => {
        reads += 1
        return Promise.resolve(reads === 1 ? linkedDoc : null)
      },
    })
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user'],
      defaultRole: 'user',
      roleManagerRoles: ['user'],
      reqUser: 'document',
      providers: [stub.provider],
      logger: nullLogger(),
    })
    const result = await authenticateWired(wired, new Headers({ cookie }), payload)
    const user = result.user as Record<string, unknown> | null
    expect(user?.id).toBe('user-1')
    expect(user?._strategy).toBe('auth-link')
    expect(user).not.toHaveProperty('createdAt')
  })

  it('memoizes the document per request context', async () => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: 'doc-2',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const findByID = vi.fn(() =>
      Promise.resolve({
        ...linkedDoc,
        activeOrganization: 'org-7',
      })
    )
    const payload = stubPayload({
      find: () =>
        Promise.resolve({
          docs: [{ ...linkedDoc, activeOrganization: 'org-7' }],
          totalDocs: 1,
        }),
      findByID,
    })
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user'],
      defaultRole: 'user',
      roleManagerRoles: ['user'],
      reqUser: 'document',
      providers: [stub.provider],
      logger: nullLogger(),
    })
    // Payload 3.83's strategy args do not declare `req` (later 3.x and
    // v4 do): build the args as a variable, typed by PayloadRequest.
    const req = { context: {} } as unknown as import('payload').PayloadRequest
    await authenticateWired(wired, new Headers({ cookie }), payload)
    const strategy = createAuthLinkStrategy(wired)
    const args = { headers: new Headers({ cookie }), payload, req }
    await strategy.authenticate(args)
    // The document is memoized on the request context, so the endpoint
    // handlers share the exact object the strategy resolved.
    const memo = req.context as Record<string, unknown>
    expect(memo['payloadAuthLink:reqUserDocument']).toBeDefined()
  })
})

it('keeps assurance, actor, and MFA markers authoritative over the document', async () => {
  const stub = createStubProvider({ capabilities: ['mfa'] })
  const cookie = stub.issue({
    sessionId: 'doc-3',
    providerUserId: 'stub-1',
    email: 'linked@test.dev',
    expiresAt: new Date(Date.now() + 3_600_000),
    mfaSatisfied: true,
    actorProviderUserId: 'operator-9',
  })
  const payload = stubPayload({
    find: () =>
      Promise.resolve({
        docs: [{ ...linkedDoc, activeOrganization: 'org-8' }],
        totalDocs: 1,
      }),
    findByID: () =>
      Promise.resolve({
        ...linkedDoc,
        activeOrganization: 'org-8',
        roles: ['admin'],
      }),
  })
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['user', 'admin'],
    defaultRole: 'user',
    roleManagerRoles: ['admin'],
    reqUser: 'document',
    providers: [stub.provider],
    logger: nullLogger(),
  })
  const result = await authenticateWired(wired, new Headers({ cookie }), payload)
  const user = result.user as Record<string, unknown> | null
  // Document fields ride along…
  expect(user?.activeOrganization).toBe('org-8')
  // …but the projected fields are authoritative, impersonation included.
  expect(user?.actor).toMatchObject({ providerUserId: 'operator-9' })
  expect(user?.assurance).toEqual({ methods: ['password'], mfa: true })
  expect(user?.roles).toEqual(['admin'])
})

it('serves the second request from the memo and honors stored projection', async () => {
  const stub = createStubProvider()
  const cookie = stub.issue({
    sessionId: 'doc-4',
    providerUserId: 'stub-1',
    email: 'linked@test.dev',
    expiresAt: new Date(Date.now() + 3_600_000),
  })
  let loads = 0
  const payload = stubPayload({
    find: () =>
      Promise.resolve({
        docs: [{ ...linkedDoc, activeOrganization: 'org-5' }],
        totalDocs: 1,
      }),
    findByID: () => {
      loads += 1
      return Promise.resolve({
        ...linkedDoc,
        activeOrganization: 'org-5',
        roles: ['front-plugin'],
      })
    },
  })
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['user', 'front-plugin'],
    defaultRole: 'user',
    roleManagerRoles: ['user'],
    reqUser: 'document',
    projectRolesAs: 'stored',
    roleValues: { 'front-plugin': 'frontPlugin' },
    providers: [stub.provider],
    logger: nullLogger(),
  })
  const strategy = createAuthLinkStrategy(wired)
  const req = { context: {} }
  const args = {
    headers: new Headers({ cookie }),
    payload,
    req: req as never,
  }
  await strategy.authenticate(args)
  const loadsAfterFirst = loads
  await strategy.authenticate(args)
  // The repository still reloads per request; the DOCUMENT load is what
  // the memo absorbs — the second request adds exactly one load.
  expect(loads).toBe(loadsAfterFirst + 1)
  const first = (await strategy.authenticate(args)).user as Record<string, unknown> | null
  // Stored projection rides through document mode too.
  expect(first?.roles).toEqual(['frontPlugin'])
  expect(loads).toBe(loadsAfterFirst + 2)
})

it('keeps the MFA marker on the document when roles were withheld', async () => {
  const stub = createStubProvider({ capabilities: ['mfa'] })
  const cookie = stub.issue({
    sessionId: 'doc-5',
    providerUserId: 'stub-1',
    email: 'linked@test.dev',
    expiresAt: new Date(Date.now() + 3_600_000),
  })
  const payload = stubPayload({
    find: () =>
      Promise.resolve({
        docs: [{ ...linkedDoc, activeOrganization: 'org-6' }],
        totalDocs: 1,
      }),
    findByID: () =>
      Promise.resolve({
        ...linkedDoc,
        activeOrganization: 'org-6',
        roles: ['admin'],
      }),
  })
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['user', 'admin'],
    defaultRole: 'user',
    roleManagerRoles: ['admin'],
    reqUser: 'document',
    policies: { requireMfaForRoles: ['admin'] },
    providers: [stub.provider],
    logger: nullLogger(),
  })
  const result = await authenticateWired(wired, new Headers({ cookie }), payload)
  const user = result.user as Record<string, unknown> | null
  // The document's stored roles are NOT authoritative: the withheld
  // role is gone and the marker explains why.
  expect(user?.roles).toEqual([])
  expect(user?.mfaRequired).toBe(true)
  expect(user?.activeOrganization).toBe('org-6')
})

describe('req.user id type', () => {
  it.each([
    ['number', 7],
    ['text', '7'],
  ] as const)('carries the %s id type of the database', async (defaultIDType, expected) => {
    const stub = createStubProvider()
    const cookie = stub.issue({
      sessionId: `id-${defaultIDType}`,
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const doc = { ...linkedDoc, id: 7 }
    const payload = stubPayload({
      defaultIDType,
      find: () => Promise.resolve({ docs: [doc], totalDocs: 1 }),
      findByID: () => Promise.resolve(doc),
    })
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [stub.provider],
      logger: nullLogger(),
    })
    const result = await authenticateWired(wired, new Headers({ cookie }), payload)
    expect((result.user as { id?: unknown } | null)?.id).toBe(expected)
  })
})
