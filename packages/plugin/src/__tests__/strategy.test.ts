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
