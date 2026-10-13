import {
  isRecord,
  parseCookieHeader,
  parseEmail,
  ProviderError,
  runProviderOperation,
  toDate,
  wellKnownProviderIds,
  type Capability,
  type CookieOptions,
  type IdentityEventEmitter,
  type IdentityProviderPort,
  type ProviderSession,
} from '@payload-auth-link/core'

/**
 * Derive declared capabilities from the Auth.js providers the
 * builder configured (PORT-2, D7 maintenance tier). The engine
 * inspects each provider's `type` (factories already resolved):
 *
 * - `email` → `'magic-link'` (CAP-1: the Email provider on this
 *   adapter's verification tokens; spike S1 proved Email+JWT and
 *   Email+database both).
 * - `oauth`/`oidc` → `'oauth'` (CAP-3; the verified-email trust
 *   policy is the engine's D6 option).
 * - a database session strategy → `'revoke-user-sessions'` (CAP-7:
 *   sessions are rows this adapter can delete; JWT sessions are
 *   stateless and honestly omit it).
 *
 * Auth.js has no native MFA, phone, anonymous, production passkey
 * (D7), or impersonation primitive — those are never declared, so a
 * policy needing them fails at wiring (D4). Assurance stays
 * `'unknown'`: Auth.js reports no per-session method or MFA.
 */
export function authJsCapabilities(input: {
  readonly providerTypes?: readonly string[] | undefined
  readonly databaseSessions?: boolean | undefined
}): ReadonlySet<Capability> {
  const capabilities = new Set<Capability>()
  for (const type of input.providerTypes ?? []) {
    if (type === 'email') {
      capabilities.add('magic-link')
    }
    if (type === 'oauth' || type === 'oidc') {
      capabilities.add('oauth')
    }
  }
  if (input.databaseSessions === true) {
    capabilities.add('revoke-user-sessions')
  }
  return capabilities
}
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
  /**
   * Revoke every database session of one user (CAP-7). The engine
   * supplies this only for the database strategy; omitted for JWT.
   */
  readonly revokeUserSessions?: ((providerUserId: string) => Promise<unknown>) | undefined
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
  /**
   * Identity lifecycle emitter (CAP-14): when present, the port
   * exposes `onIdentityEvent` subscriptions fed by the engine's
   * Auth.js `events` translation.
   */
  readonly events?: IdentityEventEmitter | undefined
  /**
   * `type` of each configured Auth.js provider (factories resolved),
   * plus whether sessions use the database strategy — the inputs to
   * {@link authJsCapabilities}. The engine fills both; direct users
   * pass them honestly. Omitted means no capabilities are declared.
   */
  readonly providerTypes?: readonly string[] | undefined
  readonly databaseSessions?: boolean | undefined
}

/**
 * Extract the presented session token: the base cookie when whole, else
 * the chunk slots joined in order (Auth.js reassembles the same way).
 * Returns null when no session cookie is present at all. A gapped chunk
 * set (`.0` and `.2` without `.1`) is malformed: joining it would hand a
 * garbage token to revocation, so it throws `ProviderError` (logged by
 * the session service as a failed read) instead.
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
  const present = chunks.map((name) => pairs.get(name))
  const lastPresent = present.reduce<number>(
    (last, value, index) => (value === undefined ? last : index),
    -1
  )
  if (lastPresent === -1) {
    return null
  }
  const contiguous = present.slice(0, lastPresent + 1)
  if (contiguous.some((value) => value === undefined)) {
    throw new ProviderError(
      wellKnownProviderIds.authjs,
      'getSession: non-contiguous session cookie chunks (missing middle slot)'
    )
  }
  const joined = contiguous.join('')
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
    identity: {
      email: { value: email.value, verified: user.emailVerified },
      phone: null,
      anonymous: false,
    },
    // Auth.js reports neither a per-session method nor MFA (D4/D7).
    assurance: { methods: 'unknown', mfa: 'unknown' },
    // Auth.js has no impersonation primitive (CAP-8/D4): never an actor.
    actor: null,
    // Auth.js has no native tenant on the session (D1 is Payload-side).
    organizationId: null,
    // Observed, not asserted: this port genuinely only reads
    // cookie-presented sessions. `extractSessionId` above requires
    // the session cookie (a cookie-less request fails the read),
    // and Auth.js's session action resolves sessions from cookies
    // only — Auth.js has no bearer-header session transport. So
    // every session that reaches this line WAS cookie-presented.
    channel: 'cookie',
  }
}

/**
 * `IdentityProviderPort` over Auth.js. Session reads go through Auth.js's
 * own session action (never a hand-rolled JWT decode): JWT signatures,
 * expiries, database lookups, and update throttling all stay upstream's
 * job. The revocable handle is the presented session token; revocation
 * deletes database sessions and is a documented no-op for stateless JWT
 * sessions (whose logout is cookie expiry at the HTTP layer).
 *
 * Channel is always `'cookie'` and that is observed, not assumed:
 * Auth.js resolves sessions from cookies only (no bearer transport),
 * and this port additionally requires the presented session cookie
 * before it returns a session at all.
 */
export function createAuthJsProvider(deps: AuthJsProviderDeps): IdentityProviderPort {
  const providerId = wellKnownProviderIds.authjs
  const cookieNames = [...deps.sessionCookieNames]
  const clearOptions = deps.sessionCookieClearOptions
  const events = deps.events
  const revokeUserSessionsFn = deps.sessions.revokeUserSessions
  return {
    id: providerId,
    capabilities: authJsCapabilities({
      providerTypes: deps.providerTypes,
      // The capability is only honest when the operation exists.
      databaseSessions: deps.databaseSessions === true && revokeUserSessionsFn !== undefined,
    }),
    sessionCookieNames: cookieNames,
    ...(clearOptions === undefined ? {} : { sessionCookieClearOptions: clearOptions }),
    ...(events === undefined ? {} : { onIdentityEvent: (handler) => events.subscribe(handler) }),
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
    ...(revokeUserSessionsFn === undefined
      ? {}
      : {
          revokeUserSessions: (providerUserId: string) =>
            runProviderOperation(
              providerId,
              'revokeUserSessions',
              () => revokeUserSessionsFn(providerUserId),
              () => undefined
            ),
        }),
  }
}
