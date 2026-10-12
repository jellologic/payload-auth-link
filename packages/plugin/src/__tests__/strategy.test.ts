import type { LoggerPort } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { createAuthLinkStrategy } from '../strategy.js'
import { wireOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

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

describe('strategy verify logging', () => {
  it('warns and returns null for an invalid session', async () => {
    const logs = capturingLogger()
    const { provider } = createStubProvider()
    const result = await authenticate(logs.logger, provider, new Headers(), stubPayload({}))
    expect(result).toEqual({ user: null })
    expect(logs.warn).toHaveBeenCalledWith('strategy verification failed: invalid session')
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
