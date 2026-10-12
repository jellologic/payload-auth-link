/**
 * Post-login redirect safety. The sign-in page receives its destination
 * as a query param, and query params are attacker-controlled input:
 * blindly pushing them is an open redirect. Every consumer of that
 * param (sign-in forms, `SignOutButton`, adapters) funnels through here.
 * Lives in core so UI packages can use it without a web dependency;
 * `@payload-auth-link/web` re-exports it unchanged.
 */

/** Destination policy for {@link safeRedirectPath}. */
export type SafeRedirectOptions = {
  /**
   * Sign-in page path. A destination equal to it (with or without a
   * query) falls back: landing a fresh login on the sign-in page loops.
   * Defaults to `/sign-in`, matching `decideAuthRedirect`. `null`
   * disables the rule for destinations where sign-in is legitimate
   * (post-sign-out navigation).
   */
  readonly signInPath?: string | null | undefined
  /**
   * API mount prefix. Destinations under it fall back: a browser
   * navigation to a JSON or mutating endpoint is never a page to land
   * on. Defaults to `/api` (Payload's default `routes.api`).
   */
  readonly apiPrefix?: string | undefined
}

function isUnder(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

/**
 * Narrow a post-login destination to a safe in-app page path. Returns
 * `value` only when it is a relative path (single leading slash, no
 * scheme, no backslashes, no control characters) that is neither the
 * sign-in page nor under the API prefix; anything else yields
 * `fallback`. Absolute URLs, protocol-relative URLs (`//evil`), and
 * values with surrounding whitespace (header/parsing differentials) all
 * fall back.
 */
export function safeRedirectPath(
  value: string | null | undefined,
  fallback: string = '/account',
  options: SafeRedirectOptions = {}
): string {
  if (typeof value !== 'string' || value === '') {
    return fallback
  }
  if (!value.startsWith('/') || value.startsWith('//')) {
    return fallback
  }
  if (value.includes('\\')) {
    return fallback
  }
  if (value.trim() !== value) {
    return fallback
  }
  for (const char of value) {
    const code = char.charCodeAt(0)
    if (code <= 0x1f || code === 0x7f) {
      return fallback
    }
  }
  const pathname = value.split(/[?#]/, 1)[0] ?? value
  const signInPath = options.signInPath === undefined ? '/sign-in' : options.signInPath
  if (signInPath !== null && pathname === signInPath) {
    return fallback
  }
  if (isUnder(pathname, options.apiPrefix ?? '/api')) {
    return fallback
  }
  return value
}
