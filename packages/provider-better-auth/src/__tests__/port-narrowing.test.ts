/**
 * Fail-closed narrowing branches of the Better Auth port that the
 * engine suites never reach (issue #113): malformed provider results,
 * missing internal-adapter functions, the signed-cookie builder's
 * context checks, and the legacy-cookie translation when nothing
 * matches. Each malformed input must surface as an error (or a
 * session miss), never as a silently "valid" value.
 */
import { InvalidConfigError, ProviderError } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import { createIdentityEventBus } from '../events.js'
import {
  createBetterAuthProvider,
  createBetterAuthProviderFromUnknown,
  type BetterAuthServerApi,
} from '../port.js'
import { nullLogger } from '@payload-auth-link/core'

const cookieNames = ['better-auth.session_token']
const live = { session: { id: 's1', token: 'tok-1', expiresAt: new Date(Date.now() + 60_000) } }

function withUser(user: Record<string, unknown>) {
  return createBetterAuthProvider({
    auth: {
      api: { getSession: () => Promise.resolve({ ...live, user }) },
      $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
    },
    sessionCookieNames: cookieNames,
  })
}

function messages(error: unknown): string {
  const parts: string[] = []
  let current: unknown = error
  while (current instanceof Error) {
    parts.push(current.message)
    current = current.cause
  }
  return parts.join(' <- ')
}

const headers = new Headers({ cookie: 'better-auth.session_token=tok' })
const base = { id: 'ba-1', email: 'user@example.com', emailVerified: true }

describe('phone claim narrowing (CAP-9)', () => {
  it('a verification flag without a number, or an empty number, is no claim', async () => {
    for (const user of [
      { ...base, phoneNumberVerified: false },
      { ...base, phoneNumber: '', phoneNumberVerified: true },
      { ...base, phoneNumber: null, phoneNumberVerified: true },
    ]) {
      const session = await withUser(user).getSession(headers)
      expect(session._unsafeUnwrap()?.identity.phone).toBeNull()
    }
  })

  it('a non-string number fails closed', async () => {
    const session = await withUser({ ...base, phoneNumber: 4155550132 }).getSession(headers)
    expect(messages(session._unsafeUnwrapErr())).toMatch(/phoneNumber is malformed/)
  })
})

describe('signed session cookie builder (#54/#72)', () => {
  function builder(context: unknown) {
    const provider = createBetterAuthProvider({
      auth: {
        api: { getSession: () => Promise.resolve(null) },
        $context: Promise.resolve(context),
      } as unknown as BetterAuthServerApi,
      sessionCookieNames: cookieNames,
    })
    // The attribute tests target the full Set-Cookie LINE (what
    // responses set); the VALUE form carries the name/attributes
    // nowhere (#125).
    const build = provider.sessionCookieLine
    if (build === undefined) {
      throw new Error('the port exposes no sessionCookieLine')
    }
    return build
  }

  it.each([
    ['a non-object context', 'context', /\$context is not an object/],
    ['no secret', { authCookies: {} }, /exposes no secret/],
    ['an empty secret', { secret: '', authCookies: {} }, /exposes no secret/],
    ['no authCookies', { secret: 's' }, /exposes no authCookies\.sessionToken/],
    ['no sessionToken', { secret: 's', authCookies: {} }, /exposes no authCookies\.sessionToken/],
    [
      'a nameless sessionToken',
      { secret: 's', authCookies: { sessionToken: { name: '' } } },
      /session cookie has no name/,
    ],
  ])('refuses to mint with %s (InvalidConfigError)', async (_label, context, message) => {
    const rejection = await builder(context)('tok').then(
      () => null,
      (error: unknown) => error
    )
    expect(rejection).toBeInstanceOf(InvalidConfigError)
    expect((rejection as Error).message).toMatch(message)
  })

  it('writes the context attributes: Path, HttpOnly, SameSite, Secure, Domain, Max-Age', async () => {
    const full = await builder({
      secret: 'secret',
      authCookies: {
        sessionToken: {
          name: '__Secure-ba.session_token',
          attributes: {
            path: '/app',
            httpOnly: true,
            sameSite: 'strict',
            secure: true,
            domain: 'example.com',
            maxAge: 3600.7,
          },
        },
      },
    })('tok')
    expect(full).toMatch(/^__Secure-ba\.session_token=tok\.[A-Za-z0-9+/=]+; /)
    expect(full.split('; ').slice(1)).toEqual([
      'Path=/app',
      'HttpOnly',
      'SameSite=Strict',
      'Secure',
      'Domain=example.com',
      'Max-Age=3600',
    ])
    const bare = await builder({
      secret: 'secret',
      authCookies: {
        sessionToken: {
          name: 'ba.session_token',
          attributes: { httpOnly: false, path: '', domain: '', sameSite: '', maxAge: Infinity },
        },
      },
    })('tok')
    expect(bare.split('; ').slice(1)).toEqual(['Path=/'])
    const noAttributes = await builder({
      secret: 'secret',
      authCookies: { sessionToken: { name: 'ba.session_token', attributes: 'odd' } },
    })('tok')
    expect(noAttributes.split('; ').slice(1)).toEqual(['Path=/', 'HttpOnly'])
  })
})

describe('legacy coexistence translation (#51) when nothing matches', () => {
  const legacySessions = {
    until: '2999-01-01T00:00:00.000Z',
    cookieNames: ['payload-auth.session_token', 'payload-auth.session_data'],
  }

  function legacyPort(getSession: (input: { headers: Headers }) => Promise<unknown>) {
    return createBetterAuthProvider({
      auth: {
        api: { getSession },
        $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
      },
      sessionCookieNames: cookieNames,
      legacySessions,
    })
  }

  it('a request without any cookie is a miss, never a provider call', async () => {
    const getSession = vi.fn(() => Promise.resolve(null))
    const result = await legacyPort(getSession).getSession(new Headers())
    expect(result._unsafeUnwrap()).toBeNull()
    expect(getSession).not.toHaveBeenCalled()
  })

  it('unrelated cookies only: a miss, never a provider call', async () => {
    const getSession = vi.fn(() => Promise.resolve(null))
    const result = await legacyPort(getSession).getSession(
      new Headers({ cookie: 'theme=dark; payload-auth.other=1' })
    )
    expect(result._unsafeUnwrap()).toBeNull()
    expect(getSession).not.toHaveBeenCalled()
  })

  it('a legacy name without a current counterpart is skipped, the matching one translated', async () => {
    const getSession = vi.fn((input: { headers: Headers }) =>
      Promise.resolve(
        input.headers.get('cookie')?.includes('better-auth.session_token=legacy')
          ? { ...live, user: base }
          : null
      )
    )
    const result = await legacyPort(getSession).getSession(
      new Headers({ cookie: 'payload-auth.session_data=x; payload-auth.session_token=legacy' })
    )
    expect(result._unsafeUnwrap()?.providerUserId).toBe('ba-1')
    expect(getSession).toHaveBeenCalledTimes(1)
  })

  it('exposes the window and the identity-event subscription on the port', () => {
    const port = createBetterAuthProvider({
      auth: {
        api: { getSession: () => Promise.resolve(null) },
        $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
      },
      sessionCookieNames: cookieNames,
      legacySessions,
      events: createIdentityEventBus(nullLogger()),
    })
    expect(port.legacySessions).toEqual(legacySessions)
    expect(typeof port.onIdentityEvent).toBe('function')
  })
})

describe('server session results (#54) fail closed when malformed', () => {
  function serverPort(internalAdapter: Record<string, unknown>) {
    return createBetterAuthProvider({
      auth: {
        api: { getSession: () => Promise.resolve(null) },
        $context: Promise.resolve({
          internalAdapter: { deleteSession: () => Promise.resolve(), ...internalAdapter },
        }),
      },
      sessionCookieNames: cookieNames,
    })
  }

  it('createProviderSession: a row without an id or a token is an error', async () => {
    for (const row of [null, { token: 't' }, { id: '', token: 't' }, { id: 'i', token: '' }]) {
      const created = await serverPort({
        createSession: () => Promise.resolve(row),
      }).createProviderSession?.('u', { expiresAt: new Date(Date.now() + 60_000) })
      expect(messages(created?._unsafeUnwrapErr())).toMatch(/expected a session row/)
    }
  })

  it('createProviderSession / listProviderSessions without the adapter function are errors', async () => {
    const port = serverPort({})
    const created = await port.createProviderSession?.('u', { expiresAt: new Date() })
    expect(messages(created?._unsafeUnwrapErr())).toMatch(/createSession is unavailable/)
    const listed = await port.listProviderSessions?.('u')
    expect(messages(listed?._unsafeUnwrapErr())).toMatch(/listSessions is unavailable/)
    const revoked = await port.revokeUserSessions?.('u')
    expect(messages(revoked?._unsafeUnwrapErr())).toMatch(/deleteUserSessions is unavailable/)
  })

  it('listProviderSessions: a non-array or an id-less entry is an error; expiry narrows', async () => {
    const notArray = await serverPort({
      listSessions: () => Promise.resolve({ sessions: [] }),
    }).listProviderSessions?.('u')
    expect(messages(notArray?._unsafeUnwrapErr())).toMatch(/expected an array/)
    const idless = await serverPort({
      listSessions: () => Promise.resolve([{ token: 't' }]),
    }).listProviderSessions?.('u')
    expect(messages(idless?._unsafeUnwrapErr())).toMatch(/expected sessions with an id/)
    const expires = new Date('2030-01-01T00:00:00.000Z')
    const listed = await serverPort({
      listSessions: () =>
        Promise.resolve([
          { id: 'a', expiresAt: expires },
          { id: 'b', expiresAt: '2030-01-01' },
        ]),
    }).listProviderSessions?.('u')
    expect(listed?._unsafeUnwrap()).toEqual([
      { sessionId: 'a', expiresAt: expires },
      { sessionId: 'b', expiresAt: null },
    ])
  })
})

describe('multi-session enumeration (CAP-13b) fails closed when malformed', () => {
  function multiPort(listDeviceSessions: () => Promise<unknown>) {
    return createBetterAuthProvider({
      auth: {
        api: { getSession: () => Promise.resolve(null), listDeviceSessions },
        $context: Promise.resolve({ internalAdapter: { deleteSession: () => Promise.resolve() } }),
      },
      sessionCookieNames: cookieNames,
    })
  }

  it('row ids win, tokens are the fallback; anything else is an error', async () => {
    const ids = await multiPort(() =>
      Promise.resolve([{ session: { id: 'row-1', token: 't1' } }, { session: { token: 't2' } }])
    ).listPresentedSessionIds?.(headers)
    expect(ids?._unsafeUnwrap()).toEqual(['row-1', 't2'])
    for (const [listed, message] of [
      [{ sessions: [] }, /expected an array/],
      [[{ user: {} }], /malformed entry/],
      [['entry'], /malformed entry/],
      [[{ session: { token: '' } }], /session token is missing/],
    ] as const) {
      const result = await multiPort(() => Promise.resolve(listed)).listPresentedSessionIds?.(
        headers
      )
      expect(messages(result?._unsafeUnwrapErr())).toMatch(message)
    }
  })
})

describe('createBetterAuthProviderFromUnknown: missing internals fail closed', () => {
  function unknownPort(resolved: unknown, api: Record<string, unknown> = {}) {
    return createBetterAuthProviderFromUnknown(
      {
        api: { getSession: () => Promise.resolve(null), ...api },
        $context: Promise.resolve(resolved),
      },
      cookieNames
    )
  }

  it.each([
    ['a non-object context', 'context'],
    ['no internalAdapter', {}],
    ['an internalAdapter without the functions', { internalAdapter: {} }],
  ])('%s: server sessions and revoke-all are errors, never no-ops', async (_label, resolved) => {
    const port = unknownPort(resolved)
    const revokeAll = await port.revokeUserSessions?.('u')
    expect(revokeAll?.isErr()).toBe(true)
    expect(revokeAll?._unsafeUnwrapErr()).toBeInstanceOf(ProviderError)
    const created = await port.createProviderSession?.('u', { expiresAt: new Date() })
    expect(created?.isErr()).toBe(true)
    const listed = await port.listProviderSessions?.('u')
    expect(listed?.isErr()).toBe(true)
  })

  it('the API-key owner gate refuses every key when findUserById is missing (#110)', async () => {
    const verify = vi.fn(() => Promise.resolve({ valid: true, key: { referenceId: 'owner-1' } }))
    const port = unknownPort(
      { internalAdapter: { deleteSession: () => Promise.resolve() } },
      { verifyApiKey: verify }
    )
    const result = await port.verifyApiKey?.('pal_key')
    expect(verify).toHaveBeenCalledWith({ body: { key: 'pal_key' } })
    expect(result?.isErr()).toBe(true)
    expect(messages(result?._unsafeUnwrapErr())).toMatch(/findUserById/)
    // With the lookup, the same key resolves its user owner.
    const gated = unknownPort(
      {
        internalAdapter: {
          deleteSession: () => Promise.resolve(),
          findUserById: (id: string) => Promise.resolve({ id }),
        },
      },
      { verifyApiKey: verify }
    )
    expect((await gated.verifyApiKey?.('pal_key'))?._unsafeUnwrap()?.userId).toBe('owner-1')
  })
})
