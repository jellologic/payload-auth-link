/**
 * Post-login redirect safety. The sign-in page receives its destination as
 * a query param (written by {@link decideAuthRedirect} for intercepted
 * paths) — but query params are attacker-controlled input, so blindly
 * pushing them is an open redirect. Every consumer of that param funnels
 * through here.
 */
import { parseCookieHeader } from '@payload-auth-link/core'

// Pure policy lives in core (UI packages need it without a web
// dependency); re-exported here so the web API is unchanged.
export { safeRedirectPath } from '@payload-auth-link/core'
export type { SafeRedirectOptions } from '@payload-auth-link/core'

/** Optimistic bounce wiring; see {@link decideAuthRedirect}. */
export type AuthRedirectOptions = {
  /**
   * Session cookie names, from the engine (`engine.sessionCookieNames`)
   * or the provider's `sessionCookieNames`. Empty names redirect
   * everything: fail closed, and wire the real names.
   */
  readonly sessionCookieNames: readonly string[]
  /** Sign-in page path. Defaults to `/sign-in` (always public). */
  readonly signInPath?: string | undefined
  /**
   * Paths that skip the check: exact strings or regexes tested against
   * `pathname`. The sign-in path is always public (no redirect loops).
   */
  readonly publicPaths?: readonly (string | RegExp)[] | undefined
  /** Query param carrying the intercepted path. Defaults to `redirect`. */
  readonly redirectParam?: string | undefined
}

/**
 * Framework-free optimistic bounce decision backing the `next` and
 * `tanstack-start` middlewares: presence of any session cookie (or a
 * public path) passes with `null`; absence yields the sign-in URL
 * carrying the intercepted path. Operates on the standard `Request`
 * (`url` + `cookie` header) so both adapters stay thin. Optimistic is
 * deliberate — the middleware cannot reach the database, so this is UX
 * (bounce obvious anonymous traffic early), never authorization.
 */
export function decideAuthRedirect(request: Request, options: AuthRedirectOptions): URL | null {
  const url = new URL(request.url)
  const signInPath = options.signInPath ?? '/sign-in'
  if (url.pathname === signInPath) {
    return null
  }
  const publicPaths = options.publicPaths ?? []
  if (
    publicPaths.some((entry) =>
      typeof entry === 'string' ? entry === url.pathname : entry.test(url.pathname)
    )
  ) {
    return null
  }
  const cookies = parseCookieHeader(request.headers.get('cookie'))
  if (options.sessionCookieNames.some((name) => cookies.has(name))) {
    return null
  }
  const signIn = new URL(signInPath, url.origin)
  // The intercepted path already carries the original query; start the
  // sign-in query fresh instead of leaking unrelated params into it.
  signIn.searchParams.set(options.redirectParam ?? 'redirect', `${url.pathname}${url.search}`)
  return signIn
}
