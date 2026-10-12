import { ProviderError, wellKnownProviderIds } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  createBetterAuthProvider,
  createBetterAuthProviderFromUnknown,
  type BetterAuthServerApi,
} from '../port.js'

const cookieNames = ['better-auth.session_token']

function api(result: unknown, overrides?: Partial<BetterAuthServerApi>): BetterAuthServerApi {
  return {
    api: { getSession: () => Promise.resolve(result) },
    $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
    ...overrides,
  }
}

const headers = new Headers({ cookie: 'better-auth.session_token=tok' })

describe('createBetterAuthProvider', () => {
  it('exposes the better-auth id and cookie names', () => {
    const provider = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    expect(provider.id).toBe(wellKnownProviderIds.betterAuth)
    expect(provider.sessionCookieNames).toEqual(cookieNames)
  })

  it('exposes clearing attributes when wired, omits the hook otherwise', () => {
    const sessionCookieClearOptions = (name: string) =>
      name === cookieNames[0] ? { secure: true as const } : undefined
    const wired = createBetterAuthProvider({
      auth: api(null),
      sessionCookieNames: cookieNames,
      sessionCookieClearOptions,
    })
    expect(wired.sessionCookieClearOptions).toBe(sessionCookieClearOptions)
    const bare = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    expect(bare.sessionCookieClearOptions).toBeUndefined()
    expect('sessionCookieClearOptions' in bare).toBe(false)
    const unknown = createBetterAuthProviderFromUnknown(
      {
        api: { getSession: () => Promise.resolve(null) },
        $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
      },
      cookieNames,
      sessionCookieClearOptions
    )
    expect(unknown.sessionCookieClearOptions).toBe(sessionCookieClearOptions)
  })

  it('narrows a live session to the revocable token handle', async () => {
    const getSession = vi.fn().mockResolvedValue({
      session: { token: 'tok-1', expiresAt: new Date('2026-02-01T00:00:00.000Z') },
      user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
    })
    const provider = createBetterAuthProvider({
      auth: api(null, { api: { getSession } }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.getSession(headers)
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value?.sessionId).toBe('tok-1')
      expect(result.value?.providerUserId).toBe('ba-1')
      expect(result.value?.email).toBe('user@example.com')
    }
    expect(getSession).toHaveBeenCalledWith({
      headers,
      query: { disableCookieCache: true, disableRefresh: true },
    })
  })

  it('returns null when there is no session', async () => {
    const provider = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    const result = await provider.getSession(headers)
    expect(result.isOk() && result.value).toBeNull()
  })

  it('accepts string and numeric expiry', async () => {
    for (const expiresAt of ['2026-02-01T00:00:00.000Z', Date.parse('2026-02-01T00:00:00.000Z')]) {
      const provider = createBetterAuthProvider({
        auth: api({
          session: { token: 'tok-1', expiresAt },
          user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
        }),
        sessionCookieNames: cookieNames,
      })
      const result = await provider.getSession(headers)
      expect(result.isOk()).toBe(true)
      if (result.isOk()) {
        expect(result.value?.expiresAt).toEqual(new Date('2026-02-01T00:00:00.000Z'))
      }
    }
  })

  it('rejects malformed sessions with ProviderError', async () => {
    const malformed = [
      { session: { expiresAt: new Date() }, user: { id: 'u', email: 'a@b.c' } },
      {
        session: { token: 't', expiresAt: 'not-a-date' },
        user: { id: 'u', email: 'a@b.c' },
      },
      {
        session: { token: 't', expiresAt: new Date('not-a-date') },
        user: { id: 'u', email: 'a@b.c', emailVerified: true },
      },
      {
        session: { token: 't', expiresAt: true },
        user: { id: 'u', email: 'a@b.c', emailVerified: true },
      },
      {
        session: { token: 't', expiresAt: new Date() },
        user: { id: 'u', email: 'not-an-email' },
      },
      {
        session: { token: 't', expiresAt: new Date() },
        user: { email: 'a@b.c', emailVerified: true },
      },
      {
        session: { token: 't', expiresAt: new Date() },
        user: { id: 'u', email: 'a@b.c' },
      },
      { session: 'not-a-record', user: { id: 'u', email: 'a@b.c', emailVerified: true } },
      42,
    ]
    for (const result of malformed) {
      const provider = createBetterAuthProvider({
        auth: api(result),
        sessionCookieNames: cookieNames,
      })
      const narrowed = await provider.getSession(headers)
      expect(narrowed.isErr()).toBe(true)
      if (narrowed.isErr()) {
        expect(narrowed.error).toBeInstanceOf(ProviderError)
      }
    }
  })

  it('wraps unexpected narrowing failures with the cause attached', async () => {
    const session: { expiresAt: Date; token?: string } = { expiresAt: new Date() }
    Object.defineProperty(session, 'token', {
      get(): string {
        throw new Error('boom')
      },
    })
    const provider = createBetterAuthProvider({
      auth: api({
        session,
        user: { id: 'u', email: 'a@b.c', emailVerified: true },
      }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.getSession(headers)
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(ProviderError)
      expect(result.error.message).toBe(
        `Provider ${wellKnownProviderIds.betterAuth} failed during getSession`
      )
      expect(result.error.cause).toBeInstanceOf(Error)
    }
  })

  it('wraps transport failures in ProviderError', async () => {
    const provider = createBetterAuthProvider({
      auth: api(null, { api: { getSession: () => Promise.reject(new Error('down')) } }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.getSession(headers)
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(ProviderError)
      expect(result.error.providerId).toBe(wellKnownProviderIds.betterAuth)
    }
  })

  it('revokes through internalAdapter.deleteSession', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const provider = createBetterAuthProvider({
      auth: api(null, {
        $context: Promise.resolve({ internalAdapter: { deleteSession } }),
      }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.revokeSession('tok-1')
    expect(result.isOk()).toBe(true)
    expect(deleteSession).toHaveBeenCalledWith('tok-1')
  })
})

describe('createBetterAuthProviderFromUnknown', () => {
  it('accepts a well-shaped instance', async () => {
    const provider = createBetterAuthProviderFromUnknown(
      {
        api: {
          getSession: () =>
            Promise.resolve({
              session: { token: 'tok-1', expiresAt: new Date('2026-02-01T00:00:00.000Z') },
              user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
            }),
        },
        $context: Promise.resolve({
          internalAdapter: { deleteSession: () => Promise.resolve() },
        }),
      },
      cookieNames
    )
    const result = await provider.getSession(headers)
    expect(result.isOk() && result.value?.sessionId).toBe('tok-1')
  })

  it('rejects misshapen instances fail-fast', () => {
    for (const auth of [
      null,
      {},
      { api: {} },
      { api: { getSession: 42 } },
      { api: { getSession: () => Promise.resolve(null) } },
    ]) {
      expect(() => createBetterAuthProviderFromUnknown(auth, cookieNames)).toThrow()
    }
  })

  it('fails revocation when $context exposes no deletable adapter', async () => {
    for (const resolved of [{}, { internalAdapter: {} }]) {
      const provider = createBetterAuthProviderFromUnknown(
        {
          api: { getSession: () => Promise.resolve(null) },
          $context: Promise.resolve(resolved),
        },
        cookieNames
      )
      const result = await provider.revokeSession('tok-1')
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(ProviderError)
      }
    }
  })
})
