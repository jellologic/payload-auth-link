import {
  InvalidConfigError,
  isRecord,
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

/** Session read input: live headers, cache and refresh disabled. */
export type BetterAuthSessionQuery = {
  headers: Headers
  query: { disableCookieCache: boolean; disableRefresh: boolean }
}

/**
 * The Better Auth server surface the port needs, stated structurally so
 * direct users pass the real instance and tests pass stubs. `getSession`
 * returns `unknown` and is narrowed below — never trusted blindly.
 */
export type BetterAuthServerApi = {
  readonly api: {
    readonly getSession: (input: BetterAuthSessionQuery) => Promise<unknown>
  }
  readonly $context: Promise<{
    readonly internalAdapter: { readonly deleteSession: (token: string) => Promise<void> }
  }>
}

/** Port wiring: the Better Auth server surface plus cookie names. */
export type BetterAuthProviderDeps = {
  readonly auth: BetterAuthServerApi
  /** From {@link getBetterAuthSessionCookieNames} (see `cookies.ts`). */
  readonly sessionCookieNames: readonly string[]
  /**
   * Clearing attributes per session cookie, from
   * {@link getBetterAuthSessionCookieClearOptions} (see `cookies.ts`).
   * Used on logout; unknown names fall back to prefix-derived attributes.
   */
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
}

type PortFunctions = {
  readonly getSession: (input: BetterAuthSessionQuery) => Promise<unknown>
  readonly deleteSession: (token: string) => Promise<unknown>
  readonly sessionCookieNames: readonly string[]
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return isRecord(value) && typeof value.then === 'function'
}

function isGetSessionFunction(
  value: unknown
): value is (input: BetterAuthSessionQuery) => Promise<unknown> {
  return typeof value === 'function'
}

function isDeleteSessionFunction(value: unknown): value is (token: string) => Promise<unknown> {
  return typeof value === 'function'
}

function narrowSession(result: unknown): ProviderSession | null {
  if (result === null) {
    return null
  }
  if (!isRecord(result)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: expected a session object or null'
    )
  }
  const { session, user } = result
  if (!isRecord(session) || !isRecord(user)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: malformed session payload'
    )
  }
  if (typeof session.token !== 'string' || session.token === '') {
    throw new ProviderError(wellKnownProviderIds.betterAuth, 'getSession: session token is missing')
  }
  const expiresAt = toDate(session.expiresAt)
  if (!expiresAt) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: session expiry is missing or invalid'
    )
  }
  if (typeof user.id !== 'string' || user.id === '') {
    throw new ProviderError(wellKnownProviderIds.betterAuth, 'getSession: user id is missing')
  }
  const email = parseEmail(user.email)
  if (email.isErr()) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      `getSession: invalid user email: ${email.error.message}`
    )
  }
  if (typeof user.emailVerified !== 'boolean') {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: emailVerified flag is missing'
    )
  }
  const narrowed: ProviderSession = {
    sessionId: session.token,
    providerUserId: user.id,
    email: email.value,
    emailVerified: user.emailVerified,
    expiresAt,
  }
  return narrowed
}

function createPortFromFunctions(deps: PortFunctions): IdentityProviderPort {
  const providerId = wellKnownProviderIds.betterAuth
  const clearOptions = deps.sessionCookieClearOptions
  return {
    id: providerId,
    sessionCookieNames: [...deps.sessionCookieNames],
    ...(clearOptions === undefined ? {} : { sessionCookieClearOptions: clearOptions }),
    getSession(headers: Headers): ResultAsync<ProviderSession | null, ProviderError> {
      return runProviderOperation(
        providerId,
        'getSession',
        () =>
          deps.getSession({ headers, query: { disableCookieCache: true, disableRefresh: true } }),
        (result) => narrowSession(result)
      )
    },
    revokeSession(sessionId: string): ResultAsync<void, ProviderError> {
      return runProviderOperation(
        providerId,
        'revokeSession',
        () => deps.deleteSession(sessionId),
        () => undefined
      )
    },
  }
}

/**
 * `IdentityProviderPort` over a Better Auth server instance. Session reads
 * bypass the cookie cache and refresh (`disableCookieCache`,
 * `disableRefresh`): the plugin verifies the authoritative database
 * session, so a revoked-but-cached session can never authorize. The
 * revocable handle is the session token, revoked through BA's own
 * `internalAdapter.deleteSession` (which also clears secondary storage).
 */
export function createBetterAuthProvider(deps: BetterAuthProviderDeps): IdentityProviderPort {
  return createPortFromFunctions({
    getSession: (input) => deps.auth.api.getSession(input),
    deleteSession: (token) =>
      deps.auth.$context.then((ctx) => ctx.internalAdapter.deleteSession(token)),
    sessionCookieNames: deps.sessionCookieNames,
    ...(deps.sessionCookieClearOptions === undefined
      ? {}
      : { sessionCookieClearOptions: deps.sessionCookieClearOptions }),
  })
}

/**
 * Same port, but the instance arrives as `unknown` and is shape-checked at
 * wiring time. The engine uses this: `Auth` is invariant in its options,
 * so a generically-typed instance cannot be converted to
 * {@link BetterAuthServerApi} statically; the runtime shape check plus the
 * engine integration tests (which run a real instance through here) close
 * the gap. Not exported from the barrel — same-package use only.
 */
export function createBetterAuthProviderFromUnknown(
  auth: unknown,
  sessionCookieNames: readonly string[],
  sessionCookieClearOptions?: (name: string) => CookieOptions | undefined
): IdentityProviderPort {
  if (!isRecord(auth)) {
    throw new InvalidConfigError('Better Auth instance must be an object')
  }
  const { api, $context } = auth
  if (!isRecord(api) || !isGetSessionFunction(api.getSession)) {
    throw new InvalidConfigError('Better Auth instance exposes no api.getSession function')
  }
  const getSession = api.getSession
  if (!isThenable($context)) {
    throw new InvalidConfigError('Better Auth instance exposes no $context promise')
  }
  const context = $context
  return createPortFromFunctions({
    getSession: (input) => getSession(input),
    deleteSession: (token) =>
      Promise.resolve(
        context.then((resolved) => {
          if (!isRecord(resolved) || !isRecord(resolved.internalAdapter)) {
            throw new InvalidConfigError('Better Auth $context exposes no internalAdapter')
          }
          const candidate: unknown = resolved.internalAdapter.deleteSession
          if (!isDeleteSessionFunction(candidate)) {
            throw new InvalidConfigError(
              'Better Auth internalAdapter exposes no deleteSession function'
            )
          }
          return candidate(token)
        })
      ),
    sessionCookieNames,
    ...(sessionCookieClearOptions === undefined ? {} : { sessionCookieClearOptions }),
  })
}
