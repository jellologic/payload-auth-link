import { createIdentityEventEmitter, nullLogger, type IdentityEvent } from '@payload-auth-link/core'
import type { JWT } from '@auth/core/jwt'
import type { Session } from '@auth/core/types'
import { describe, expect, it, vi } from 'vitest'
import {
  createAuthLinkCallbacks,
  createAuthLinkEvents,
  emailVerifiedClaim,
  type AuthLinkCallbacks,
} from '../callbacks.js'

type JwtParams = Parameters<AuthLinkCallbacks['jwt']>[0]
type SessionParams = Parameters<AuthLinkCallbacks['session']>[0]

const STAMPED = new Date('2026-02-03T00:00:00.000Z')

function fakeUpdateUser() {
  return vi.fn((user: { id: string; emailVerified?: Date | null }) =>
    Promise.resolve({
      id: user.id,
      email: 'a@b.co',
      emailVerified: user.emailVerified ?? null,
    })
  )
}

function oauthJwtParams(overrides: Record<string, unknown> = {}): JwtParams {
  return {
    token: jwtToken({}),
    user: { id: 'au-1', email: 'a@b.co', emailVerified: null },
    account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
    profile: { email: 'a@b.co', email_verified: true },
    trigger: 'signIn',
    ...overrides,
  }
}

function jwtToken(claims: Record<string, unknown>): JWT {
  return claims
}

function sessionShape(user: Record<string, unknown>): Session {
  return { user, expires: new Date(Date.now() + 3600_000).toISOString() }
}

describe('jwt claims callback', () => {
  it('stamps subject and verification at sign-in', async () => {
    const { jwt } = createAuthLinkCallbacks()
    const token = await jwt({
      token: jwtToken({}),
      user: { id: 'au-1', email: 'a@b.co', emailVerified: new Date('2026-01-02T00:00:00.000Z') },
    })
    expect(token).not.toBeNull()
    if (token !== null) {
      expect(token.sub).toBe('au-1')
      expect(token[emailVerifiedClaim]).toBe('2026-01-02T00:00:00.000Z')
    }
  })

  it('stamps null verification for unverified users', async () => {
    const { jwt } = createAuthLinkCallbacks()
    const token = await jwt({
      token: jwtToken({}),
      user: { id: 'au-1', email: 'a@b.co', emailVerified: null },
    })
    if (token !== null) {
      expect(token[emailVerifiedClaim]).toBeNull()
    }
  })

  it('preserves claims on session reads where user is absent', async () => {
    const { jwt } = createAuthLinkCallbacks()
    const token = await jwt({
      token: jwtToken({ [emailVerifiedClaim]: '2026-01-02T00:00:00.000Z' }),
    } as JwtParams)
    expect(token).toMatchObject({ [emailVerifiedClaim]: '2026-01-02T00:00:00.000Z' })
  })

  it('runs the builder callback first and respects forced logout', async () => {
    const seen: unknown[] = []
    const builderJwt = vi.fn((params: JwtParams): Promise<JWT | null> => {
      seen.push(params.user?.id)
      return Promise.resolve(params.token)
    })
    const { jwt } = createAuthLinkCallbacks({ jwt: builderJwt })
    const token = await jwt({
      token: jwtToken({}),
      user: { id: 'au-1', email: 'a@b.co', emailVerified: null },
    })
    expect(builderJwt).toHaveBeenCalledTimes(1)
    expect(seen).toEqual(['au-1'])
    expect(token).not.toBeNull()

    const logout = vi.fn((): Promise<JWT | null> => Promise.resolve(null))
    const forced = await createAuthLinkCallbacks({ jwt: logout }).jwt({
      token: jwtToken({}),
    } as JwtParams)
    expect(forced).toBeNull()
    expect(logout).toHaveBeenCalledTimes(1)
  })
})

describe('session claims callback', () => {
  it('surfaces id and verification from the token', async () => {
    const { session } = createAuthLinkCallbacks()
    const resolved = await session({
      session: sessionShape({ name: 'A', email: 'a@b.co' }),
      token: jwtToken({ sub: 'au-1', [emailVerifiedClaim]: '2026-01-02T00:00:00.000Z' }),
    } as SessionParams)
    expect(resolved.user).toMatchObject({
      id: 'au-1',
      name: 'A',
      email: 'a@b.co',
      emailVerified: true,
    })
  })

  it('reports unverified and omits id when the token lacks them', async () => {
    const { session } = createAuthLinkCallbacks()
    const resolved = await session({
      session: sessionShape({ name: 'A' }),
      token: jwtToken({ [emailVerifiedClaim]: null }),
    } as SessionParams)
    expect(resolved.user).toMatchObject({ name: 'A', emailVerified: false })
    expect(resolved.user?.id).toBeUndefined()
  })

  it('reads id and verification from the adapter row on database strategy', async () => {
    const { session } = createAuthLinkCallbacks()
    const resolved = await session({
      session: sessionShape({ name: 'A', email: 'a@b.co' }),
      user: { id: 'au-7', email: 'a@b.co', emailVerified: new Date('2026-01-02T00:00:00.000Z') },
    } as unknown as SessionParams)
    expect(resolved.user).toMatchObject({
      id: 'au-7',
      name: 'A',
      email: 'a@b.co',
      emailVerified: true,
    })
  })

  it('reports unverified for a database row with null emailVerified', async () => {
    const { session } = createAuthLinkCallbacks()
    const resolved = await session({
      session: sessionShape({ name: 'A', email: 'a@b.co' }),
      user: { id: 'au-7', email: 'a@b.co', emailVerified: null },
    } as unknown as SessionParams)
    expect(resolved.user).toMatchObject({ id: 'au-7', emailVerified: false })
  })

  it('runs the builder session first and wins on its own keys', async () => {
    const builderSession = vi.fn((params: SessionParams): Promise<Session> =>
      Promise.resolve({
        ...params.session,
        user: { ...params.session.user, name: 'Builder', emailVerified: true },
      })
    )
    const { session } = createAuthLinkCallbacks({ session: builderSession })
    const resolved = await session({
      session: sessionShape({ name: 'A' }),
      token: jwtToken({ sub: 'au-9', [emailVerifiedClaim]: null }),
    } as SessionParams)
    expect(builderSession).toHaveBeenCalledTimes(1)
    // Builder customizations survive; the claims layer owns id/verification.
    expect(resolved.user).toMatchObject({ name: 'Builder', id: 'au-9', emailVerified: false })
  })
})

describe('trusted provider email verification (CAP-3a / D6)', () => {
  it('stamps through updateUser for an allow-listed provider asserting email_verified', async () => {
    const updateUser = fakeUpdateUser()
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const token = await jwt(oauthJwtParams())
    expect(updateUser).toHaveBeenCalledTimes(1)
    expect(updateUser.mock.calls[0]?.[0].id).toBe('au-1')
    expect(updateUser.mock.calls[0]?.[0].emailVerified).toBeInstanceOf(Date)
    // The first JWT already carries the stamped date, not a fabricated claim.
    const claim = token?.[emailVerifiedClaim]
    expect(typeof claim).toBe('string')
    expect(claim).toBe(updateUser.mock.calls[0]?.[0].emailVerified?.toISOString())
  })

  it('never stamps when the allow-listed provider asserts email_verified false (R6)', async () => {
    const updateUser = fakeUpdateUser()
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const token = await jwt(oauthJwtParams({ profile: { email: 'a@b.co', email_verified: false } }))
    expect(updateUser).not.toHaveBeenCalled()
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('never stamps when email_verified is absent or not strictly true', async () => {
    const updateUser = fakeUpdateUser()
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    for (const profile of [{ email: 'a@b.co' }, { email: 'a@b.co', email_verified: 'true' }]) {
      const token = await jwt(oauthJwtParams({ profile }))
      expect(token?.[emailVerifiedClaim]).toBeNull()
    }
    expect(updateUser).not.toHaveBeenCalled()
  })

  it('never stamps for a provider outside the allow-list', async () => {
    const updateUser = fakeUpdateUser()
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['acme-oidc'],
      updateUser,
    })
    const token = await jwt(oauthJwtParams())
    expect(updateUser).not.toHaveBeenCalled()
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('never stamps by default (no trust option)', async () => {
    const { jwt } = createAuthLinkCallbacks()
    const token = await jwt(oauthJwtParams())
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('never stamps a user whose email differs from the verified profile email', async () => {
    const updateUser = fakeUpdateUser()
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const token = await jwt(
      oauthJwtParams({
        user: { id: 'au-1', email: 'victim@b.co', emailVerified: null },
        profile: { email: 'attacker@b.co', email_verified: true },
      })
    )
    expect(updateUser).not.toHaveBeenCalled()
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('does not re-stamp an already verified user', async () => {
    const updateUser = fakeUpdateUser()
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const token = await jwt(
      oauthJwtParams({
        user: { id: 'au-1', email: 'a@b.co', emailVerified: STAMPED },
      })
    )
    expect(updateUser).not.toHaveBeenCalled()
    expect(token?.[emailVerifiedClaim]).toBe(STAMPED.toISOString())
  })

  it('stamps on the signIn event for database sessions and chains the builder event', async () => {
    const updateUser = fakeUpdateUser()
    const builderSignIn = vi.fn(() => Promise.resolve())
    const events = createAuthLinkEvents(
      { signIn: builderSignIn },
      { trustProviderEmailVerification: ['google'], updateUser }
    )
    await events.signIn?.({
      user: { id: 'au-2', email: 'a@b.co' },
      account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
      profile: { email: 'A@b.co', email_verified: true },
    })
    expect(builderSignIn).toHaveBeenCalledTimes(1)
    expect(updateUser).toHaveBeenCalledTimes(1)
    expect(updateUser.mock.calls[0]?.[0].id).toBe('au-2')
  })

  it('does not stamp on the signIn event when email_verified is false', async () => {
    const updateUser = fakeUpdateUser()
    const events = createAuthLinkEvents(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    await events.signIn?.({
      user: { id: 'au-2', email: 'a@b.co' },
      account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
      profile: { email: 'a@b.co', email_verified: false },
    })
    expect(updateUser).not.toHaveBeenCalled()
  })
})

describe('identity lifecycle events (CAP-14)', () => {
  it('translates updateUser and linkAccount, chaining builder events first', async () => {
    const emitter = createIdentityEventEmitter()
    const seen: IdentityEvent[] = []
    emitter.subscribe((event) => {
      seen.push(event)
      return Promise.resolve()
    })
    const builderUpdate = vi.fn(() => Promise.resolve())
    const events = createAuthLinkEvents({ updateUser: builderUpdate }, undefined, {
      emitter,
      logger: nullLogger(),
    })
    await events.updateUser?.({
      user: { id: 'au-7', email: 'fresh@example.com', emailVerified: STAMPED } as never,
    })
    expect(builderUpdate).toHaveBeenCalledTimes(1)
    expect(seen[0]).toMatchObject({ type: 'email-changed', providerUserId: 'au-7', verified: true })
    await events.updateUser?.({
      user: { id: 'au-7', email: 'fresh@example.com', emailVerified: null } as never,
    })
    expect(seen[1]).toMatchObject({ type: 'email-changed', verified: false })
    await events.linkAccount?.({
      user: { id: 'au-7', email: 'fresh@example.com', emailVerified: STAMPED },
      account: { provider: 'google', type: 'oidc', providerAccountId: 'g-9' },
      profile: { email: 'fresh@example.com' },
    })
    expect(seen[2]).toMatchObject({ type: 'email-verified', providerUserId: 'au-7' })
    await events.linkAccount?.({
      user: { id: 'au-7', email: 'fresh@example.com', emailVerified: null },
      account: { provider: 'google', type: 'oidc', providerAccountId: 'g-9' },
      profile: { email: 'fresh@example.com' },
    })
    expect(seen).toHaveLength(3)
  })
})
