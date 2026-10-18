/**
 * Security guards in the Auth.js claims layer (issue #110): the D6
 * stamp never claims a verification the adapter did not store, and
 * the CAP-14 event translation never emits for unusable user rows or
 * without a lifecycle sink.
 */
import {
  createIdentityEventEmitter,
  nullLogger,
  type IdentityEvent,
  type LoggerPort,
} from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  createAuthLinkCallbacks,
  createAuthLinkEvents,
  emailVerifiedClaim,
  type AuthLinkCallbacks,
  type AuthLinkEvents,
} from '../callbacks.js'

type JwtParams = Parameters<AuthLinkCallbacks['jwt']>[0]
type UpdateUserMessage = Parameters<AuthLinkEvents['updateUser']>[0]
type LinkAccountMessage = Parameters<AuthLinkEvents['linkAccount']>[0]

function oauthJwtParams(): JwtParams {
  return {
    token: {},
    user: { id: 'au-1', email: 'a@b.co', emailVerified: null },
    account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
    profile: { email: 'a@b.co', email_verified: true },
    trigger: 'signIn',
  }
}

function recordingSink() {
  const emitter = createIdentityEventEmitter()
  const seen: IdentityEvent[] = []
  emitter.subscribe((event) => {
    seen.push(event)
    return Promise.resolve()
  })
  const warnings: string[] = []
  const logger: LoggerPort = {
    ...nullLogger(),
    warn: (message) => {
      warnings.push(message)
    },
  }
  return { lifecycle: { emitter, logger }, seen, warnings }
}

describe('D6 stamp trusts only the adapter-stored date', () => {
  it.each([
    { label: 'the user has no email', user: { email: null }, profile: {} },
    { label: 'the profile has no email', user: {}, profile: { email: null } },
    { label: 'the user email is blank', user: { email: '   ' }, profile: {} },
    { label: 'the profile email is blank', user: {}, profile: { email: '' } },
    { label: 'the emails differ', user: {}, profile: { email: 'other@b.co' } },
  ])('never stamps when $label', async ({ user, profile }) => {
    const updateUser = vi.fn((row: { id: string }) =>
      Promise.resolve({ id: row.id, email: 'a@b.co', emailVerified: new Date() })
    )
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const base = oauthJwtParams()
    const token = await jwt({
      ...base,
      user: { ...base.user, ...user },
      profile: { ...base.profile, ...profile },
    })
    expect(updateUser).not.toHaveBeenCalled()
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('matches emails case- and whitespace-insensitively', async () => {
    const updateUser = vi.fn((row: { id: string }) =>
      Promise.resolve({ id: row.id, email: 'a@b.co', emailVerified: new Date() })
    )
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const base = oauthJwtParams()
    const token = await jwt({ ...base, profile: { ...base.profile, email: ' A@B.CO ' } })
    expect(updateUser).toHaveBeenCalledTimes(1)
    expect(typeof token?.[emailVerifiedClaim]).toBe('string')
  })

  it('claims nothing when updateUser does not return a verified date', async () => {
    // The adapter accepted the write but reports no verification
    // (e.g. a builder adapter that ignores the field): the token must
    // not claim one, and the shared user object is left unverified.
    const updateUser = vi.fn((user: { id: string }) =>
      Promise.resolve({ id: user.id, email: 'a@b.co', emailVerified: null })
    )
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const params = oauthJwtParams()
    const token = await jwt(params)
    expect(updateUser).toHaveBeenCalledTimes(1)
    expect(token?.[emailVerifiedClaim]).toBeNull()
    expect((params.user as { emailVerified?: unknown }).emailVerified).toBeNull()
  })

  it('a non-Date verification value from the adapter is not a stamp', async () => {
    const updateUser = vi.fn((user: { id: string }) =>
      Promise.resolve({
        id: user.id,
        email: 'a@b.co',
        emailVerified: '2026-01-01T00:00:00.000Z' as unknown as Date,
      })
    )
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const token = await jwt(oauthJwtParams())
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('an adapter failure propagates, never downgrading silently', async () => {
    const updateUser = vi.fn(() => Promise.reject(new Error('adapter down')))
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    await expect(jwt(oauthJwtParams())).rejects.toThrow('adapter down')
  })
})

describe('CAP-14 event translation refuses unusable rows', () => {
  const unusable: readonly [string, unknown][] = [
    ['null', null],
    ['a non-object', 'au-1'],
    ['a missing id', { email: 'a@b.co', emailVerified: new Date() }],
    ['an empty id', { id: '', email: 'a@b.co', emailVerified: new Date() }],
    ['a non-string id', { id: 7, email: 'a@b.co', emailVerified: new Date() }],
    ['a missing email', { id: 'au-1', emailVerified: new Date() }],
    ['an invalid email', { id: 'au-1', email: 'not-an-email', emailVerified: new Date() }],
  ]

  for (const [label, user] of unusable) {
    it(`updateUser with ${label} is logged and skipped`, async () => {
      const sink = recordingSink()
      const events = createAuthLinkEvents(undefined, undefined, sink.lifecycle)
      await events.updateUser({ user } as unknown as UpdateUserMessage)
      expect(sink.seen).toEqual([])
      expect(sink.warnings).toEqual(['authjs updateUser event: unusable user row, event skipped'])
    })

    it(`linkAccount with ${label} emits nothing`, async () => {
      const sink = recordingSink()
      const events = createAuthLinkEvents(undefined, undefined, sink.lifecycle)
      await events.linkAccount({
        user,
        account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
        profile: { email: 'a@b.co' },
      } as unknown as LinkAccountMessage)
      expect(sink.seen).toEqual([])
    })
  }

  it('an unverified email change is emitted unverified (the applier ignores it)', async () => {
    const sink = recordingSink()
    const events = createAuthLinkEvents(undefined, undefined, sink.lifecycle)
    await events.updateUser({
      user: { id: 'au-2', email: 'NEW@Example.com', emailVerified: null },
    } as unknown as UpdateUserMessage)
    expect(sink.seen).toEqual([
      {
        type: 'email-changed',
        providerId: 'authjs',
        providerUserId: 'au-2',
        email: 'new@example.com',
        verified: false,
      },
    ])
  })

  it('without a lifecycle sink, builder events still run and nothing is emitted', async () => {
    const builderUpdate = vi.fn(() => Promise.resolve())
    const builderLink = vi.fn(() => Promise.resolve())
    const events = createAuthLinkEvents({ updateUser: builderUpdate, linkAccount: builderLink })
    const user = { id: 'au-3', email: 'a@b.co', emailVerified: new Date() }
    await events.updateUser({ user })
    await events.linkAccount({
      user,
      account: { provider: 'google', type: 'oidc', providerAccountId: 'g-3' },
      profile: { email: 'a@b.co' },
    } as unknown as LinkAccountMessage)
    expect(builderUpdate).toHaveBeenCalledTimes(1)
    expect(builderLink).toHaveBeenCalledTimes(1)
  })

  it('a builder event failure propagates before anything is emitted', async () => {
    const sink = recordingSink()
    const events = createAuthLinkEvents(
      { updateUser: () => Promise.reject(new Error('builder failed')) },
      undefined,
      sink.lifecycle
    )
    await expect(
      events.updateUser({
        user: { id: 'au-4', email: 'a@b.co', emailVerified: new Date() },
      } as unknown as UpdateUserMessage)
    ).rejects.toThrow('builder failed')
    expect(sink.seen).toEqual([])
  })
})

describe('builder session results are scrubbed of the database session token', () => {
  type SessionParams = Parameters<AuthLinkCallbacks['session']>[0]
  type BuilderSession = NonNullable<
    NonNullable<Parameters<typeof createAuthLinkCallbacks>[0]>['session']
  >
  const TOKEN = 'live-session-token-0123456789'

  /** Database-strategy params: the adapter row merged with the user, no token. */
  function databaseParams(sessionToken: string = TOKEN): SessionParams {
    const user = { id: 'au-1', email: 'a@b.co', emailVerified: null }
    return {
      session: { sessionToken, userId: 'au-1', expires: new Date(), user },
      user,
    } as unknown as SessionParams
  }

  async function run(
    builder: (params: SessionParams) => unknown,
    params: SessionParams = databaseParams()
  ): Promise<Record<string, unknown>> {
    const { session } = createAuthLinkCallbacks({ session: builder as BuilderSession })
    return (await session(params)) as unknown as Record<string, unknown>
  }

  it('removes nested sessionToken keys and token-bearing strings, keeping the rest', async () => {
    const resolved = await run((params) => ({
      ...params.session,
      deep: { a: { sessionToken: 'other', kept: 1, copy: TOKEN } },
      list: [TOKEN, { note: `cookie=${TOKEN}` }, 'kept', null, 3],
      when: new Date('2026-01-01T00:00:00.000Z'),
    }))
    expect(JSON.stringify(resolved)).not.toContain(TOKEN)
    expect(resolved).not.toHaveProperty('sessionToken')
    expect(resolved).not.toHaveProperty('userId')
    expect(resolved.deep).toEqual({ a: { kept: 1 } })
    expect(resolved.list).toEqual([{}, 'kept', null, 3])
    expect(resolved.when).toBe('2026-01-01T00:00:00.000Z')
    expect(resolved.user).toMatchObject({ id: 'au-1', emailVerified: false })
  })

  it('copies a value shared by two branches instead of treating it as a cycle', async () => {
    const shared = { theme: 'dark' }
    const resolved = await run((params) => ({ ...params.session, a: shared, b: [shared] }))
    expect(resolved.a).toEqual({ theme: 'dark' })
    expect(resolved.b).toEqual([{ theme: 'dark' }])
  })

  it('fails loudly on a cyclic result instead of recursing forever', async () => {
    const cyclic: Record<string, unknown> = { theme: 'dark' }
    cyclic.self = cyclic
    await expect(run((params) => ({ ...params.session, cyclic }))).rejects.toMatchObject({
      code: 'SESSION_SHAPE_INVALID',
    })
  })

  it('fails loudly when toJSON turns the result into a non-object', async () => {
    await expect(run(() => ({ toJSON: () => 'not a session' }))).rejects.toMatchObject({
      code: 'SESSION_SHAPE_INVALID',
    })
  })

  it('treats an empty session token as no token instead of removing every string', async () => {
    const resolved = await run(
      (params) => ({ ...params.session, theme: 'dark' }),
      databaseParams('')
    )
    expect(resolved.theme).toBe('dark')
  })
})
