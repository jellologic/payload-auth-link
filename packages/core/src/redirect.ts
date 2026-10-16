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
   * query, or a trailing slash) falls back: landing a fresh login on
   * the sign-in page loops. Defaults to `/sign-in`, matching
   * `decideAuthRedirect`. `null` disables the rule for destinations
   * where sign-in is legitimate (post-sign-out navigation).
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

/** Opaque base for resolving relative destinations; never emitted. */
const normalizationOrigin = 'http://redirect.invalid'

function hasControlCharacter(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0)
    if (code <= 0x1f || code === 0x7f) {
      return true
    }
  }
  return false
}

/**
 * Resolve a path the way a browser (and the server's router) will:
 * dot segments collapse (`/x/../api` is `/api`, `/%2e%2e/api` is
 * `/api`). `undefined` when the result is not a same-origin path.
 */
function resolveSameOrigin(path: string): URL | undefined {
  let url: URL
  try {
    url = new URL(path, normalizationOrigin)
  } catch {
    return undefined
  }
  if (url.origin !== normalizationOrigin) {
    return undefined
  }
  // `/.//evil` normalises to `//evil`: protocol-relative again.
  if (!url.pathname.startsWith('/') || url.pathname.startsWith('//')) {
    return undefined
  }
  return url
}

/**
 * Narrow a post-login destination to a safe in-app page path. Accepts
 * only a relative path (single leading slash, no scheme, no
 * backslashes, no control characters). The path is then normalised as
 * a browser would resolve it — dot segments (`.`/`..`, including
 * percent-encoded `%2e`) collapse — and the result must still be a
 * same-origin path that is neither the sign-in page nor under the API
 * prefix, also after percent-decoding (routers decode before
 * matching). Returns the NORMALISED path with its query and hash;
 * anything else yields `fallback`. Absolute URLs, protocol-relative
 * URLs (`//evil`), and values with surrounding whitespace
 * (header/parsing differentials) all fall back.
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
  if (value.trim() !== value || hasControlCharacter(value)) {
    return fallback
  }
  const url = resolveSameOrigin(value)
  if (url === undefined) {
    return fallback
  }
  const pathname = url.pathname
  let decoded: string
  try {
    decoded = decodeURIComponent(pathname)
  } catch {
    return fallback
  }
  if (decoded.includes('\\') || hasControlCharacter(decoded)) {
    return fallback
  }
  const decodedUrl = resolveSameOrigin(decoded)
  if (decodedUrl === undefined) {
    return fallback
  }
  const signInPath = options.signInPath === undefined ? '/sign-in' : options.signInPath
  const apiPrefix = options.apiPrefix ?? '/api'
  for (const candidate of [pathname, decodedUrl.pathname]) {
    if (signInPath !== null && (candidate === signInPath || candidate === `${signInPath}/`)) {
      return fallback
    }
    if (isUnder(candidate, apiPrefix)) {
      return fallback
    }
  }
  return `${pathname}${url.search}${url.hash}`
}
