import type { JWT } from '@auth/core/jwt'
import type { Session } from '@auth/core/types'
import { describe, expect, it, vi } from 'vitest'
import {
  createAuthLinkCallbacks,
  emailVerifiedClaim,
  type AuthLinkCallbacks,
} from '../callbacks.js'

type JwtParams = Parameters<AuthLinkCallbacks['jwt']>[0]
type SessionParams = Parameters<AuthLinkCallbacks['session']>[0]

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
