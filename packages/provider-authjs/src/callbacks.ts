import type { AuthConfig } from '@auth/core'
import type { Adapter } from '@auth/core/adapters'
import {
  parseEmail,
  wellKnownProviderIds,
  type Email,
  type IdentityEventEmitter,
  type LoggerPort,
} from '@payload-auth-link/core'
import { SessionShapeError } from './errors.js'

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
type SignInEvent = NonNullable<NonNullable<AuthConfig['events']>['signIn']>
type UpdateUserEvent = NonNullable<NonNullable<AuthConfig['events']>['updateUser']>
type LinkAccountEvent = NonNullable<NonNullable<AuthConfig['events']>['linkAccount']>

/** Chained jwt/session callbacks carrying the port's claims. */
export type AuthLinkCallbacks = {
  readonly jwt: JwtCallback
  readonly session: SessionCallback
}

/** Chained Auth.js events carrying trust stamping + CAP-14 translation. */
export type AuthLinkEvents = {
  readonly signIn: SignInEvent
  readonly updateUser: UpdateUserEvent
  readonly linkAccount: LinkAccountEvent
}

/** CAP-14 lifecycle sink for {@link createAuthLinkEvents}. */
export type AuthLinkLifecycle = {
  readonly emitter: IdentityEventEmitter
  readonly logger: LoggerPort
}

/**
 * D6 trust options for the claims layer. `trustProviderEmailVerification`
 * is an allow-list of OAuth/OIDC provider ids whose `email_verified`
 * profile claim may stamp the adapter user's `emailVerified` (through
 * `updateUser`). Empty or absent means never stamp — the default.
 */
export type AuthLinkTrustOptions = {
  readonly trustProviderEmailVerification?: readonly string[] | undefined
  readonly updateUser?: NonNullable<Adapter['updateUser']> | undefined
}

type StampCandidate = {
  readonly user: {
    readonly id?: string | undefined
    readonly email?: string | null | undefined
  }
  readonly account?:
    | {
        readonly provider?: string | undefined
        readonly type?: string | undefined
      }
    | null
    | undefined
  readonly profile?:
    | {
        readonly email?: string | null | undefined
        readonly email_verified?: unknown
      }
    | undefined
}

function normalizeEmail(email: string | null | undefined): string | null {
  if (typeof email !== 'string') {
    return null
  }
  const normalized = email.trim().toLowerCase()
  return normalized === '' ? null : normalized
}

/**
 * Stamp `emailVerified` through the adapter when — and only when —
 * every D6 guard holds: the provider is allow-listed, the account is
 * OAuth/OIDC, the raw profile asserts `email_verified === true`, the
 * profile email is the user's own email, and the user is not already
 * verified. Returns the stamped date, or null when any guard fails.
 * The date comes from the adapter's updated user, never invented here:
 * if `updateUser` does not return a verified date, nothing is claimed.
 * Adapter failures propagate (fail the sign-in loudly, never silently
 * downgrade to unverified).
 */
async function stampTrustedEmailVerification(
  trust: AuthLinkTrustOptions | undefined,
  candidate: StampCandidate
): Promise<Date | null> {
  const updateUser = trust?.updateUser
  const trusted = trust?.trustProviderEmailVerification ?? []
  const { user, account, profile } = candidate
  if (
    updateUser === undefined ||
    account === null ||
    account === undefined ||
    (account.type !== 'oauth' && account.type !== 'oidc') ||
    account.provider === undefined ||
    !trusted.includes(account.provider) ||
    profile === undefined ||
    profile.email_verified !== true ||
    typeof user.id !== 'string' ||
    user.id === ''
  ) {
    return null
  }
  const smuggled = user as { emailVerified?: unknown }
  if (smuggled.emailVerified instanceof Date) {
    return null
  }
  const userEmail = normalizeEmail(user.email)
  const profileEmail = normalizeEmail(profile.email)
  if (userEmail === null || profileEmail === null || userEmail !== profileEmail) {
    return null
  }
  const updated = await updateUser({ id: user.id, emailVerified: new Date() })
  if (!(updated.emailVerified instanceof Date)) {
    return null
  }
  // Keep the shared user object honest so the later `signIn` event in
  // the same flow sees the stamp and does not write twice.
  ;(user as { emailVerified?: unknown }).emailVerified = updated.emailVerified
  return updated.emailVerified
}

type SessionShape = Awaited<ReturnType<SessionCallback>>
type SessionUser = NonNullable<SessionShape['user']>

/**
 * The response shape Auth.js's own default `session` callback builds:
 * `user` reduced to `name` / `email` / `image`, plus `expires`. The
 * database strategy hands the callback the adapter session row
 * (`sessionToken`, `userId`, …) merged with the user row; none of that
 * is copied, so the session JSON carries no credential. `expires`
 * arrives as a `Date` on database sessions and is serialized the way
 * upstream does.
 */
function allowlistedSession(input: SessionShape): SessionShape {
  const source: SessionUser = input.user ?? {}
  const user: SessionUser = {
    ...(source.name === undefined ? {} : { name: source.name }),
    ...(source.email === undefined ? {} : { email: source.email }),
    ...(source.image === undefined ? {} : { image: source.image }),
  }
  const expires: unknown = input.expires
  return { user, expires: expires instanceof Date ? expires.toISOString() : input.expires }
}

/** Top-level fields of the Auth.js adapter session row. */
const sessionRowFields = ['sessionToken', 'userId', 'id'] as const

/** Marks a value the scrub removed (distinct from a legitimate `undefined`). */
const removed: unique symbol = Symbol('removed')

function hasToJSON(value: object): value is { toJSON: (key: string) => unknown } {
  return typeof (value as { toJSON?: unknown }).toJSON === 'function'
}

/**
 * One value of a builder session result, as `JSON.stringify` would see
 * it (`toJSON` applied, own enumerable keys), with the credential
 * removed: every `sessionToken` key, and every string that contains the
 * live session token, at any depth. `ancestors` is the path from the
 * root, so a cycle (which `JSON.stringify` rejects too) fails loudly
 * while a value shared by two branches is simply copied twice.
 */
function scrubValue(
  value: unknown,
  key: string,
  sessionToken: string | null,
  ancestors: object[]
): unknown {
  const current: unknown =
    typeof value === 'object' && value !== null && hasToJSON(value) ? value.toJSON(key) : value
  if (typeof current === 'string') {
    return sessionToken !== null && current.includes(sessionToken) ? removed : current
  }
  if (typeof current !== 'object' || current === null) {
    return current
  }
  if (ancestors.includes(current)) {
    throw new SessionShapeError('the result contains a cyclic reference')
  }
  ancestors.push(current)
  try {
    if (Array.isArray(current)) {
      const items: unknown[] = []
      current.forEach((item: unknown, index) => {
        const scrubbed = scrubValue(item, String(index), sessionToken, ancestors)
        if (scrubbed !== removed) {
          items.push(scrubbed)
        }
      })
      return items
    }
    const kept: Record<string, unknown> = {}
    for (const [entryKey, entry] of Object.entries(current)) {
      if (entryKey === 'sessionToken') {
        continue
      }
      const scrubbed = scrubValue(entry, entryKey, sessionToken, ancestors)
      if (scrubbed !== removed) {
        kept[entryKey] = scrubbed
      }
    }
    return kept
  } finally {
    ancestors.pop()
  }
}

/**
 * A builder `session` callback's result made safe to send. The adapter
 * session row fields (`sessionToken`, `userId`, `id`) are removed at
 * the top level, so a builder returning `{ ...session, … }` keeps the
 * response to session data. The credential is removed at ANY depth —
 * every `sessionToken` key and every string containing the live
 * database session token — so a builder that nests the session
 * (`{ ...s, debug: { s } }`) or copies the token under another key
 * cannot leak it. Everything else the builder returns is kept, in its
 * JSON form (the response is JSON, so `Date`s become ISO strings).
 */
function scrubBuilderSession(result: SessionShape, sessionToken: string | null): SessionShape {
  const top = { ...result }
  for (const field of sessionRowFields) {
    Reflect.deleteProperty(top, field)
  }
  const scrubbed = scrubValue(top, '', sessionToken, [])
  if (typeof scrubbed !== 'object' || scrubbed === null || Array.isArray(scrubbed)) {
    throw new SessionShapeError('the result is not an object')
  }
  // Scrubbing only removes keys and array items from the builder's own
  // (session-typed) result; the claims layer re-asserts `user.id` and
  // `user.emailVerified` on top of it.
  return scrubbed as SessionShape
}

/** The live database session token Auth.js handed the callback, if any. */
function liveSessionToken(session: object): string | null {
  const token: unknown = (session as { sessionToken?: unknown }).sessionToken
  return typeof token === 'string' && token !== '' ? token : null
}

/**
 * Chain the builder's callbacks (if any) with the claims the port needs.
 * The builder's callbacks run FIRST on raw values; the claims layer then
 * wins on its own keys so a builder callback can never silently break
 * the port contract. A builder jwt callback returning `null` (forced
 * logout) is respected as-is.
 *
 * The session response is built from an allowlist, never by spreading
 * what Auth.js passes in: without a builder `session` callback it is
 * `{ user: { name, email, image, id, emailVerified }, expires }` (the
 * Auth.js default shape plus the port's two claims); with one, the
 * builder's result is kept except for the adapter session row fields
 * `sessionToken`, `userId` and `id` at the top level and — at any
 * depth — every `sessionToken` key and every string containing the
 * live database session token, which are always removed. Either way
 * `user.id` and `user.emailVerified` come from the claims layer.
 *
 * Spike findings encoded here: the jwt callback re-runs on every session
 * read WITHOUT `user` (the token re-encodes), so claims are stuffed only
 * when `user` is present — otherwise the re-encoded token loses them.
 *
 * D6 (CAP-3a): upstream `handle-login` creates OAuth users with
 * `emailVerified: null` whatever the IdP asserts, and the oauth jwt
 * invocation is the one point that has the adapter user, the account,
 * AND the raw profile (`email_verified`) before the first token is
 * encoded — so trusted stamping happens here, and the token claim is
 * the date the adapter actually stored.
 */
export function createAuthLinkCallbacks(
  builder?: AuthConfig['callbacks'],
  trust?: AuthLinkTrustOptions
): AuthLinkCallbacks {
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
    const stamped = await stampTrustedEmailVerification(trust, {
      user: params.user,
      account: params.account,
      profile: params.profile,
    })
    const smuggled = params.user as { emailVerified?: unknown }
    const verified =
      stamped ?? (smuggled.emailVerified instanceof Date ? smuggled.emailVerified : null)
    token[emailVerifiedClaim] = verified === null ? null : verified.toISOString()
    return token
  }

  const session: SessionCallback = async (params) => {
    const resolved = builder?.session
      ? scrubBuilderSession(await builder.session(params), liveSessionToken(params.session))
      : allowlistedSession(params.session)
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

/**
 * Chain the builder's `signIn` event with D6 trusted stamping. Database
 * sessions never run the jwt callback at sign-in, so this event (which
 * upstream fires with the adapter user and the raw OAuth profile on
 * every OAuth callback) is their stamp point; later session reads then
 * load the stamped row. On JWT flows the jwt callback stamps first and
 * this becomes a no-op. The builder's event runs first, matching the
 * callbacks convention.
 */
export function createAuthLinkEvents(
  builder?: AuthConfig['events'],
  trust?: AuthLinkTrustOptions,
  lifecycle?: AuthLinkLifecycle
): AuthLinkEvents {
  const signIn: SignInEvent = async (message) => {
    await builder?.signIn?.(message)
    await stampTrustedEmailVerification(trust, {
      user: message.user,
      account: message.account,
      profile: message.profile,
    })
  }
  // CAP-14 translation. Upstream fires `updateUser` after adapter
  // user updates and `linkAccount` after an account links; it does
  // NOT invoke `unlinkAccount`/`deleteUser` events yet, so Auth.js
  // cannot produce `identity-unlinked`/`user-deleted` today — those
  // stay covered by read-time behavior (a deleted provider user
  // simply stops resolving sessions). Observations never throw into
  // the Auth.js flow: unusable rows are logged and skipped.
  const narrowEventUser = (
    value: unknown
  ): { id: string; email: Email; verified: boolean } | null => {
    if (typeof value !== 'object' || value === null) {
      return null
    }
    const record = value as Record<string, unknown>
    const email = typeof record.email === 'string' ? parseEmail(record.email) : null
    if (typeof record.id !== 'string' || record.id === '' || email === null || email.isErr()) {
      return null
    }
    return { id: record.id, email: email.value, verified: record.emailVerified instanceof Date }
  }
  const updateUser: UpdateUserEvent = async (message) => {
    await builder?.updateUser?.(message)
    if (lifecycle === undefined) {
      return
    }
    const user = narrowEventUser(message.user)
    if (user === null) {
      lifecycle.logger.warn('authjs updateUser event: unusable user row, event skipped')
      return
    }
    await lifecycle.emitter.emit({
      type: 'email-changed',
      providerId: wellKnownProviderIds.authjs,
      providerUserId: user.id,
      email: user.email,
      verified: user.verified,
    })
  }
  const linkAccount: LinkAccountEvent = async (message) => {
    await builder?.linkAccount?.(message)
    if (lifecycle === undefined) {
      return
    }
    const user = narrowEventUser(message.user)
    if (user === null || !user.verified) {
      return
    }
    await lifecycle.emitter.emit({
      type: 'email-verified',
      providerId: wellKnownProviderIds.authjs,
      providerUserId: user.id,
      email: user.email,
    })
  }
  return { signIn, updateUser, linkAccount }
}
