import { ProviderError, wellKnownProviderIds } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  betterAuthCapabilities,
  createBetterAuthProvider,
  createBetterAuthProviderFromUnknown,
  isPlaceholderEmail,
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

  it('fills PORT-1 identity/assurance/channel claims and PORT-2 capabilities', async () => {
    const provider = createBetterAuthProvider({
      auth: api({
        session: {
          token: 'tok-1',
          expiresAt: new Date('2026-02-01T00:00:00.000Z'),
          activeOrganizationId: 'org-1',
        },
        user: {
          id: 'ba-1',
          email: 'user@example.com',
          emailVerified: true,
          twoFactorEnabled: true,
        },
      }),
      sessionCookieNames: cookieNames,
    })
    // No plugin declared at this seam: only the core
    // revoke-user-sessions capability is claimed (PORT-2 honesty).
    expect(provider.capabilities).toEqual(
      new Set(['revoke-user-sessions', 'server-session-create', 'server-session-list'])
    )
    expect(provider.revokeUserSessions).toBeTypeOf('function')
    const result = await provider.getSession(headers)
    expect(result.isOk()).toBe(true)
    if (result.isOk() && result.value !== null) {
      expect(result.value.identity).toEqual({
        email: { value: 'user@example.com', verified: true },
        phone: null,
        anonymous: false,
      })
      // Assurance reads the recorded per-session method, never the
      // enrollment flag: this fixture records no method, so the
      // session proves nothing — even with twoFactorEnabled: true on
      // the user.
      expect(result.value.assurance).toEqual({ methods: 'unknown', mfa: 'unknown' })
      expect(result.value.organizationId).toBe('org-1')
      expect(result.value.channel).toBe('cookie')
      expect(result.value.actor).toBeNull()
    } else {
      expect.unreachable('expected a narrowed session')
    }
  })

  it('defaults mfa to unknown and organizationId to null when undeclared (S3/PORT-1)', async () => {
    for (const [session, user] of [
      [
        { token: 'tok-1', expiresAt: new Date() },
        { id: 'ba-1', email: 'user@example.com', emailVerified: true },
      ],
      [
        { token: 'tok-1', expiresAt: new Date(), activeOrganizationId: null },
        { id: 'ba-1', email: 'user@example.com', emailVerified: false, twoFactorEnabled: null },
      ],
    ] as const) {
      const provider = createBetterAuthProvider({
        auth: api({ session, user }),
        sessionCookieNames: cookieNames,
      })
      const result = await provider.getSession(headers)
      expect(result.isOk()).toBe(true)
      if (result.isOk() && result.value !== null) {
        expect(result.value.organizationId).toBeNull()
        expect(result.value.assurance.methods).toBe('unknown')
        expect(result.value.assurance.mfa).toBe('unknown')
      }
    }
  })

  it('fails closed on malformed PORT-1 claim sources', async () => {
    const expiresAt = new Date()
    const malformed = [
      {
        session: { token: 'tok-1', expiresAt, activeOrganizationId: 42 },
        user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
      },
      {
        session: { token: 'tok-1', expiresAt, authenticationMethod: 42 },
        user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
      },
      {
        session: { token: 'tok-1', expiresAt },
        user: { id: 'ba-1', email: 'user@example.com', emailVerified: true, isAnonymous: 'no' },
      },
    ]
    for (const body of malformed) {
      const provider = createBetterAuthProvider({
        auth: api(body),
        sessionCookieNames: cookieNames,
      })
      const result = await provider.getSession(headers)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(ProviderError)
      }
    }
  })

  it('declares impersonation only when the admin plugin is wired (PORT-2)', () => {
    const bare = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    expect(bare.capabilities.has('impersonation')).toBe(false)
    const withAdmin = createBetterAuthProvider({
      auth: api(null),
      sessionCookieNames: cookieNames,
      impersonation: true,
    })
    expect(withAdmin.capabilities).toEqual(
      new Set([
        'impersonation',
        'revoke-user-sessions',
        'server-session-create',
        'server-session-list',
      ])
    )
    const unknownBare = createBetterAuthProviderFromUnknown(
      {
        api: { getSession: () => Promise.resolve(null) },
        $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
      },
      cookieNames
    )
    expect(unknownBare.capabilities.has('impersonation')).toBe(false)
  })

  it('observes the channel: bearer header without session cookie is bearer (CAP-13a)', async () => {
    const body = {
      session: { token: 'tok-1', expiresAt: new Date() },
      user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
    }
    const provider = createBetterAuthProvider({
      auth: api(body),
      sessionCookieNames: cookieNames,
    })
    const bearerOnly = await provider.getSession(
      new Headers({ authorization: 'Bearer [REDACTED]' })
    )
    expect(bearerOnly.isOk() && bearerOnly.value?.channel).toBe('bearer')
    // Fail-closed: a presented Bearer [REDACTED] makes the channel
    // bearer even with a session cookie: BA's bearer plugin
    // overwrites the cookie from the header, so a dummy cookie
    // must not launder a header presentation into cookie.
    const both = await provider.getSession(
      new Headers({
        authorization: 'Bearer [REDACTED]',
        cookie: 'better-auth.session_token=tok',
      })
    )
    expect(both.isOk() && both.value?.channel).toBe('bearer')
    const dummyCookie = await provider.getSession(
      new Headers({
        authorization: 'Bear' + 'er tok',
        cookie: 'better-auth.session_token=',
      })
    )
    expect(dummyCookie.isOk() && dummyCookie.value?.channel).toBe('bearer')
    const cookieOnly = await provider.getSession(headers)
    expect(cookieOnly.isOk() && cookieOnly.value?.channel).toBe('cookie')
    const noBearer = await provider.getSession(new Headers({ authorization: 'Basic xyz' }))
    expect(noBearer.isOk() && noBearer.value?.channel).toBe('cookie')
  })

  it('maps session.impersonatedBy to actor, and its absence to actor null (CAP-8a)', async () => {
    const user = { id: 'ba-1', email: 'user@example.com', emailVerified: true }
    const expiresAt = new Date('2026-02-01T00:00:00.000Z')
    const impersonated = createBetterAuthProvider({
      auth: api({ session: { token: 'tok-1', expiresAt, impersonatedBy: 'ba-admin' }, user }),
      sessionCookieNames: cookieNames,
    })
    const impersonatedResult = await impersonated.getSession(headers)
    expect(impersonatedResult.isOk() && impersonatedResult.value?.actor).toEqual({
      providerUserId: 'ba-admin',
    })
    for (const session of [
      { token: 'tok-1', expiresAt },
      { token: 'tok-1', expiresAt, impersonatedBy: null },
    ]) {
      const plain = createBetterAuthProvider({
        auth: api({ session, user }),
        sessionCookieNames: cookieNames,
      })
      const plainResult = await plain.getSession(headers)
      expect(plainResult.isOk() && plainResult.value?.actor).toBeNull()
    }
  })

  it('fails closed on a malformed impersonatedBy instead of dropping it (CAP-8a)', async () => {
    const user = { id: 'ba-1', email: 'user@example.com', emailVerified: true }
    for (const impersonatedBy of [42, '', true]) {
      const provider = createBetterAuthProvider({
        auth: api({
          session: { token: 'tok-1', expiresAt: new Date(), impersonatedBy },
          user,
        }),
        sessionCookieNames: cookieNames,
      })
      const result = await provider.getSession(headers)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(ProviderError)
      }
    }
  })

  it('exposes logout cookie names when wired, omits them otherwise', () => {
    const logoutCookieNames = ['better-auth.admin_session']
    const wired = createBetterAuthProvider({
      auth: api(null),
      sessionCookieNames: cookieNames,
      logoutCookieNames,
    })
    expect(wired.logoutCookieNames).toEqual(logoutCookieNames)
    expect(wired.logoutCookieNames).not.toBe(logoutCookieNames)
    const bare = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    expect('logoutCookieNames' in bare).toBe(false)
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

  it('revokes through internalAdapter.deleteSession, verified both directions', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const findSessions = vi
      .fn()
      .mockResolvedValueOnce([{ session: { token: 'tok-1' }, user: { id: 'ba-1' } }])
      .mockResolvedValueOnce([])
    const provider = createBetterAuthProvider({
      auth: api(null, {
        $context: Promise.resolve({ internalAdapter: { deleteSession, findSessions } }),
      }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.revokeSession('tok-1')
    expect(result.isOk()).toBe(true)
    expect(deleteSession).toHaveBeenCalledWith('tok-1')
    // A revocation with NO row behind it is an error, not a silent
    // success (nothing was deleted).
    const second = await provider.revokeSession('tok-1')
    expect(second.isErr()).toBe(true)
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

  it('maps phone claims (CAP-9): verified E.164 only, malformed types fail closed', async () => {
    const withUser = (user: Record<string, unknown>) =>
      createBetterAuthProvider({
        auth: api({
          session: { token: 'tok-1', expiresAt: new Date('2026-02-01T00:00:00.000Z') },
          user,
        }),
        sessionCookieNames: cookieNames,
      })
    const base = { id: 'ba-1', email: 'user@example.com', emailVerified: true }
    const verified = await withUser({
      ...base,
      phoneNumber: '+14155550132',
      phoneNumberVerified: true,
    }).getSession(headers)
    expect(verified._unsafeUnwrap()?.identity.phone).toEqual({
      value: '+14155550132',
      verified: true,
    })
    const national = await withUser({
      ...base,
      phoneNumber: '415-555-0132',
      phoneNumberVerified: true,
    }).getSession(headers)
    expect(national._unsafeUnwrap()?.identity.phone).toBeNull()
    const malformed = await withUser({ ...base, phoneNumberVerified: 'yes' }).getSession(headers)
    expect(malformed.isErr()).toBe(true)
  })

  it('treats placeholder emails as guest identities with no email claim (CAP-10/17)', async () => {
    expect(isPlaceholderEmail('temp-1@anonymous.placeholder.invalid')).toBe(true)
    expect(isPlaceholderEmail('0xabc@siwe.placeholder.invalid')).toBe(true)
    expect(isPlaceholderEmail('user@example.com')).toBe(false)
    const provider = createBetterAuthProvider({
      auth: api({
        session: { token: 'tok-1', expiresAt: new Date('2026-02-01T00:00:00.000Z') },
        user: {
          id: 'ba-anon',
          email: 'temp-1@anonymous.placeholder.invalid',
          emailVerified: false,
        },
      }),
      sessionCookieNames: cookieNames,
    })
    const session = (await provider.getSession(headers))._unsafeUnwrap()
    expect(session?.identity.email).toBeNull()
    expect(session?.identity.anonymous).toBe(true)
  })

  it('observes the api-key channel from the x-api-key header (CAP-13)', async () => {
    const provider = createBetterAuthProvider({
      auth: api({
        session: { token: 'tok-1', expiresAt: new Date('2026-02-01T00:00:00.000Z') },
        user: { id: 'ba-1', email: 'user@example.com', emailVerified: true },
      }),
      sessionCookieNames: cookieNames,
    })
    const session = (
      await provider.getSession(new Headers({ 'x-api-key': 'key-1' }))
    )._unsafeUnwrap()
    expect(session?.channel).toBe('api-key')
  })

  it('revokes every session of a user through the internal adapter (CAP-7)', async () => {
    const deleteUserSessions = vi.fn(() => Promise.resolve())
    const provider = createBetterAuthProvider({
      auth: api(null, {
        $context: Promise.resolve({
          internalAdapter: { deleteSession: () => Promise.resolve(), deleteUserSessions },
        }),
      }),
      sessionCookieNames: cookieNames,
    })
    expect((await provider.revokeUserSessions?.('ba-1'))?.isOk()).toBe(true)
    expect(deleteUserSessions).toHaveBeenCalledWith('ba-1')
    // A narrow stub without the method fails typed, never silently.
    const narrow = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    expect((await narrow.revokeUserSessions?.('ba-1'))?.isErr()).toBe(true)
  })

  it('enumerates multi-session handles and presented multi cookies (CAP-13b)', async () => {
    const provider = createBetterAuthProvider({
      auth: api(null, {
        api: {
          getSession: () => Promise.resolve(null),
          listDeviceSessions: () =>
            Promise.resolve([
              { session: { token: 'tok-a' }, user: { id: 'ba-1' } },
              { session: { token: 'tok-b' }, user: { id: 'ba-2' } },
            ]),
        },
      }),
      sessionCookieNames: cookieNames,
    })
    const multiHeaders = new Headers({
      cookie:
        'better-auth.session_token=tok-a; better-auth.session_token_multi-tok-a=x; better-auth.session_token_multi-tok-b=y; other=1',
    })
    expect((await provider.listPresentedSessionIds?.(multiHeaders))?._unsafeUnwrap()).toEqual([
      'tok-a',
      'tok-b',
    ])
    expect(provider.presentedLogoutCookieNames?.(multiHeaders)).toEqual([
      'better-auth.session_token_multi-tok-a',
      'better-auth.session_token_multi-tok-b',
    ])
    const bare = createBetterAuthProvider({ auth: api(null), sessionCookieNames: cookieNames })
    expect(bare.listPresentedSessionIds).toBeUndefined()
    expect(bare.presentedLogoutCookieNames).toBeUndefined()
  })

  it('derives capabilities from installed plugin ids (PORT-2)', () => {
    expect([...betterAuthCapabilities({})]).toEqual([
      'revoke-user-sessions',
      'server-session-create',
      'server-session-list',
    ])
    expect(
      [
        ...betterAuthCapabilities({ plugins: ['magic-link', 'two-factor', 'unknown-plugin'] }),
      ].sort()
    ).toEqual([
      'magic-link',
      'mfa',
      'revoke-user-sessions',
      'server-session-create',
      'server-session-list',
    ])
    expect(betterAuthCapabilities({ oauth: true }).has('oauth')).toBe(true)
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
