import type { AuthConfig } from '@auth/core'

declare module '@auth/core/types' {
  // The documented Auth.js pattern (self-contained: no imports, which
  // keeps the augmentation visible to every consumer of this module):
  // the port's just-in-time linking gates on email verification, so
  // the session carries the flag.
  interface Session {
    user?: {
      id?: string
      name?: string | null
      email?: string | null
      image?: string | null
      emailVerified?: boolean | null | undefined
    }
  }
}

/** JWT claim carrying the verification timestamp (ISO string) or null. */
export const emailVerifiedClaim = 'authLinkEmailVerified'

type JwtCallback = NonNullable<NonNullable<AuthConfig['callbacks']>['jwt']>
type SessionCallback = NonNullable<NonNullable<AuthConfig['callbacks']>['session']>

/** Chained jwt/session callbacks carrying the port's claims. */
export type AuthLinkCallbacks = {
  readonly jwt: JwtCallback
  readonly session: SessionCallback
}

/**
 * Chain the builder's callbacks (if any) with the claims the port needs.
 * The builder's callbacks run FIRST on raw values; the claims layer then
 * wins on its own keys so a builder callback can never silently break
 * the port contract. A builder jwt callback returning `null` (forced
 * logout) is respected as-is.
 *
 * Spike findings encoded here: the jwt callback re-runs on every session
 * read WITHOUT `user` (the token re-encodes), so claims are stuffed only
 * when `user` is present — otherwise the re-encoded token loses them.
 */
export function createAuthLinkCallbacks(builder?: AuthConfig['callbacks']): AuthLinkCallbacks {
  const jwt: JwtCallback = async (params) => {
    const token = builder?.jwt ? await builder.jwt(params) : params.token
    if (token === null) {
      return null
    }
    if (params.user === undefined) {
      return token
    }
    if (params.user.id !== undefined) {
      token.sub = params.user.id
    }
    const smuggled = params.user as { emailVerified?: unknown }
    token[emailVerifiedClaim] =
      smuggled.emailVerified instanceof Date ? smuggled.emailVerified.toISOString() : null
    return token
  }

  const session: SessionCallback = async (params) => {
    const resolved = builder?.session ? await builder.session(params) : params.session
    if (params.token === undefined) {
      // Database strategy: no token — Auth.js passes the adapter user
      // row instead, so identity and verification come from it. (The
      // Auth.js types intersect both shapes, so this reads as
      // unreachable to the compiler; at runtime it is the only path
      // database deployments take.)
      const user = params.user
      return {
        ...resolved,
        user: {
          ...resolved.user,
          id: user.id,
          emailVerified: user.emailVerified instanceof Date,
        },
      }
    }
    return {
      ...resolved,
      user: {
        ...resolved.user,
        ...(params.token.sub === undefined ? {} : { id: params.token.sub }),
        emailVerified: typeof params.token[emailVerifiedClaim] === 'string',
      },
    }
  }

  return { jwt, session }
}
