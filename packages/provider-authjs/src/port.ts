import {
  isRecord,
  parseCookieHeader,
  parseEmail,
  ProviderError,
  runProviderOperation,
  toDate,
  wellKnownProviderIds,
  type CookieOptions,
  type IdentityProviderPort,
  type ProviderSession,
} from '@payload-auth-link/core'
import type { ResultAsync } from 'neverthrow'

/**
 * The Auth.js server surface the port needs, stated as injected
 * functions: the engine binds these to `Auth()` with its config, so the
 * port never imports Auth.js and stays unit-testable with stubs.
 */
export type AuthJsSessionApi = {
  /** Read the session through Auth.js's own session action (or null). */
  readonly readSession: (headers: Headers) => Promise<unknown>
  /** Revoke a database session token; a no-op for JWT sessions. */
  readonly revokeSession: (sessionId: string) => Promise<unknown>
}

/** Port wiring: the Auth.js session surface plus cookie names. */
export type AuthJsProviderDeps = {
  readonly sessions: AuthJsSessionApi
  /** From {@link getAuthJsSessionCookieNames} (see `cookies.ts`). */
  readonly sessionCookieNames: readonly string[]
  /**
   * Clearing attributes per session cookie, from
   * {@link getAuthJsSessionCookieClearOptions} (see `cookies.ts`). Used on
   * logout; unknown names fall back to prefix-derived attributes.
   */
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
}

/**
 * Extract the presented session token: the base cookie when whole, else
 * the chunk slots joined in order (Auth.js reassembles the same way).
 * Returns null when no session cookie is present at all.
 */
function extractSessionId(headers: Headers, cookieNames: readonly string[]): string | null {
  const header = headers.get('cookie')
  if (!header) {
    return null
  }
  const [base, ...chunks] = cookieNames
  const pairs = parseCookieHeader(header)
  if (base !== undefined) {
    const direct = pairs.get(base)
    if (direct !== undefined) {
      return direct
    }
  }
  const joined = chunks.map((name) => pairs.get(name) ?? '').join('')
  return joined === '' ? null : joined
}

function narrowSession(
  result: unknown,
  headers: Headers,
  cookieNames: readonly string[]
): ProviderSession | null {
  if (result === null) {
    return null
  }
  if (!isRecord(result)) {
    throw new ProviderError(
      wellKnownProviderIds.authjs,
      'getSession: expected a session object or null'
    )
  }
  const { user, expires } = result
  if (!isRecord(user)) {
    throw new ProviderError(wellKnownProviderIds.authjs, 'getSession: malformed session payload')
  }
  if (typeof user.id !== 'string' || user.id === '') {
    throw new ProviderError(wellKnownProviderIds.authjs, 'getSession: user id is missing')
  }
  const email = parseEmail(user.email)
  if (email.isErr()) {
    throw new ProviderError(
      wellKnownProviderIds.authjs,
      `getSession: invalid user email: ${email.error.message}`
    )
  }
  if (typeof user.emailVerified !== 'boolean') {
    throw new ProviderError(
      wellKnownProviderIds.authjs,
      'getSession: emailVerified flag is missing (the engine session callback must surface it)'
    )
  }
  const expiresAt = toDate(expires)
  if (!expiresAt) {
    throw new ProviderError(
      wellKnownProviderIds.authjs,
      'getSession: session expiry is missing or invalid'
    )
  }
  const sessionId = extractSessionId(headers, cookieNames)
  if (!sessionId) {
    throw new ProviderError(
      wellKnownProviderIds.authjs,
      'getSession: session without a presented session cookie'
    )
  }
  return {
    sessionId,
    providerUserId: user.id,
    email: email.value,
    emailVerified: user.emailVerified,
    expiresAt,
  }
}

/**
 * `IdentityProviderPort` over Auth.js. Session reads go through Auth.js's
 * own session action (never a hand-rolled JWT decode): JWT signatures,
 * expiries, database lookups, and update throttling all stay upstream's
 * job. The revocable handle is the presented session token; revocation
 * deletes database sessions and is a documented no-op for stateless JWT
 * sessions (whose logout is cookie expiry at the HTTP layer).
 */
export function createAuthJsProvider(deps: AuthJsProviderDeps): IdentityProviderPort {
  const providerId = wellKnownProviderIds.authjs
  const cookieNames = [...deps.sessionCookieNames]
  const clearOptions = deps.sessionCookieClearOptions
  return {
    id: providerId,
    sessionCookieNames: cookieNames,
    ...(clearOptions === undefined ? {} : { sessionCookieClearOptions: clearOptions }),
    getSession(headers: Headers): ResultAsync<ProviderSession | null, ProviderError> {
      return runProviderOperation(
        providerId,
        'getSession',
        () => deps.sessions.readSession(headers),
        (result) => narrowSession(result, headers, cookieNames)
      )
    },
    revokeSession(sessionId: string): ResultAsync<void, ProviderError> {
      return runProviderOperation(
        providerId,
        'revokeSession',
        () => deps.sessions.revokeSession(sessionId),
        () => undefined
      )
    },
  }
}
