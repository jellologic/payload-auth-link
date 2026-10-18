import {
  hostCookiePrefix,
  resolveSecureCookies,
  secureCookiePrefix,
  type CookieOptions,
  type SecureCookieEnvironment,
} from '@payload-auth-link/core'
import type { BetterAuthOptions } from 'better-auth'

// The core value import above is Edge-safe: `secureCookiePrefix` and
// `resolveSecureCookies` are a const and a pure function with no
// framework or Node imports, and tree-shaken bundlers drop the rest of
// the core barrel from the `cookies` subpath.

const defaultCookiePrefix = 'better-auth'

/** The Better Auth options that influence cookie names. */
export type BetterAuthCookieOptions = Pick<BetterAuthOptions, 'advanced' | 'baseURL' | 'session'>

/** Session-indicating Better Auth cookies. */
type SessionCookieKey = 'session_token' | 'session_data'

/**
 * The admin plugin's impersonation cookie key. BA sets it (via
 * `createAuthCookie('admin_session')`) to the impersonating operator's
 * signed session token when impersonation starts. It is NOT
 * session-indicating — the live session is still `session_token` — so
 * it never joins {@link getBetterAuthSessionCookieNames}; it is a
 * logout-clearing concern only (see {@link getBetterAuthLogoutCookieNames}).
 */
const adminSessionCookieKey = 'admin_session'

/**
 * Non-session cookies BA sets that a logout must still expire:
 * `admin_session` (above), `dont_remember` (set on a sign-in
 * without "remember me"; BA's own sign-out deletes it) and
 * `account_data` (the account cookie cache, set when
 * `account.storeAccountCookie` is on; BA's own sign-out deletes it).
 */
const auxiliaryCookieKeys = [adminSessionCookieKey, 'dont_remember', 'account_data'] as const
type AuxiliaryCookieKey = (typeof auxiliaryCookieKeys)[number]

function readDynamicProtocol(baseURL: BetterAuthOptions['baseURL']): string | undefined {
  if (typeof baseURL !== 'object' || baseURL === null || !('protocol' in baseURL)) {
    return undefined
  }
  const protocol: unknown = baseURL.protocol
  return typeof protocol === 'string' ? protocol : undefined
}

/**
 * Whether BA sets secure cookies, via the shared production-secure rule
 * (`useSecureCookies` ?? dynamic protocol ?? https baseURL ??
 * `NODE_ENV=production`) — the same inputs BA's own `createCookieGetter`
 * reads, in the same order. The cookie-suite drift test asserts these
 * names against that real getter option for option.
 */
function secureCookiesEnabled(
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): boolean {
  const baseURL = typeof options.baseURL === 'string' ? options.baseURL : undefined
  return resolveSecureCookies(
    {
      useSecureCookies: options.advanced?.useSecureCookies,
      baseURL,
      dynamicProtocol: readDynamicProtocol(options.baseURL),
    },
    // The core rule takes no globals: the adapter injects the live env
    // (inlined by Edge bundlers, like BA's own load-time read).
    { nodeEnv: environment?.nodeEnv ?? process.env.NODE_ENV }
  )
}

/**
 * Session cookie keys with their resolved names, mirroring BA's
 * `createCookieGetter` exactly: per-cookie `advanced.cookies.*.name`
 * overrides win, otherwise `{cookiePrefix}.{session_token|session_data}`,
 * prefixed with `__Secure-` when secure cookies apply.
 *
 * `session_data` (cookie cache) is included only when enabled — it
 * defaults to off. The cookie-suite drift test asserts these names
 * against BA's real cookie getter to catch upstream drift.
 */
function sessionCookieEntries(
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): Array<{ readonly key: SessionCookieKey; readonly name: string }> {
  const entries: Array<{ readonly key: SessionCookieKey; readonly name: string }> = [
    { key: 'session_token', name: sessionCookieName('session_token', options, environment) },
  ]
  if (options.session?.cookieCache?.enabled === true) {
    entries.push({
      key: 'session_data',
      name: sessionCookieName('session_data', options, environment),
    })
  }
  return entries
}

/** One session cookie key's resolved name (see `sessionCookieEntries`). */
function sessionCookieName(
  key: SessionCookieKey,
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): string {
  const prefix = options.advanced?.cookiePrefix || defaultCookiePrefix
  const secure = secureCookiesEnabled(options, environment) ? secureCookiePrefix : ''
  return `${secure}${options.advanced?.cookies?.[key]?.name || `${prefix}.${key}`}`
}

/**
 * A non-session cookie's resolved name, mirroring BA's
 * `createCookieGetter` for that key exactly: the
 * `advanced.cookies.<key>.name` override wins, otherwise
 * `{cookiePrefix}.<key>`, prefixed with `__Secure-` when secure cookies
 * apply. The drift test asserts these against BA's real getter.
 */
function auxiliaryCookieName(
  key: AuxiliaryCookieKey,
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): string {
  const prefix = options.advanced?.cookiePrefix || defaultCookiePrefix
  const secure = secureCookiesEnabled(options, environment) ? secureCookiePrefix : ''
  const override: unknown = options.advanced?.cookies?.[key]?.name
  return `${secure}${typeof override === 'string' && override !== '' ? override : `${prefix}.${key}`}`
}

/** The same cookie name under the other `__Secure-` setting. */
function toggledSecureVariant(name: string): string | undefined {
  if (name.startsWith(hostCookiePrefix)) {
    return undefined
  }
  return name.startsWith(secureCookiePrefix)
    ? name.slice(secureCookiePrefix.length)
    : `${secureCookiePrefix}${name}`
}

/**
 * Cookies to expire on logout that do not indicate a live session (the
 * port's `logoutCookieNames`):
 *
 * - the admin plugin's `admin_session` (the impersonating operator's
 *   resumable session token);
 * - `dont_remember` (sign-in without "remember me");
 * - `account_data` (the account cookie cache, when
 *   `account.storeAccountCookie` is on);
 * - the cookie-cache `session_data`, even when the cache is disabled
 *   now — it may have been enabled when the cookie was set;
 * - the `__Secure-` / plain counterpart of every session and logout
 *   name, so a deployment that switched between http and https (or
 *   toggled `useSecureCookies`) leaves no residue under the other
 *   name.
 *
 * Expired unconditionally — a cookie that was never set makes its
 * clearing write a no-op. Chunks of these cookies (`<name>.0` …) are
 * per-request and enumerated from the presented Cookie header by the
 * port's `presentedLogoutCookieNames`.
 */
export function getBetterAuthLogoutCookieNames(
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): readonly string[] {
  const sessionNames = getBetterAuthSessionCookieNames(options, environment)
  const sessionDataName = sessionCookieName('session_data', options, environment)
  const base = [
    ...auxiliaryCookieKeys.map((key) => auxiliaryCookieName(key, options, environment)),
    ...(sessionNames.includes(sessionDataName) ? [] : [sessionDataName]),
  ]
  const names = new Set(base)
  for (const name of [...sessionNames, ...base]) {
    const toggled = toggledSecureVariant(name)
    if (toggled !== undefined && !sessionNames.includes(toggled)) {
      names.add(toggled)
    }
  }
  return [...names]
}

/**
 * Session cookie names for a Better Auth instance. See
 * `sessionCookieEntries` for the mirroring rule; the cookie-suite drift
 * test asserts these against BA's real cookie getter.
 */
export function getBetterAuthSessionCookieNames(
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): readonly string[] {
  return sessionCookieEntries(options, environment).map((entry) => entry.name)
}

/**
 * Logout clearing lookup: the live overwrite attributes per session
 * cookie. Attribute precedence mirrors BA: per-cookie
 * `advanced.cookies.*.attributes` win, then
 * `advanced.defaultCookieAttributes`, then the secure default above.
 * Unknown names yield `undefined` so the caller falls back to
 * `expiringCookieOptions`.
 *
 * `crossSubDomainCookies` is mirrored like BA's `createCookieGetter`:
 * when enabled, every cookie is written with `Domain` set to
 * `crossSubDomainCookies.domain`, or the static `baseURL`'s hostname —
 * underneath `defaultCookieAttributes` and per-cookie attributes, which
 * still win. Without the matching `Domain` a clearing write misses the
 * cookie, and the browser keeps the cookie-cache `session_data` that
 * BA's own `/get-session` keeps answering from until it expires.
 * Residual: a dynamic `baseURL` (`allowedHosts`) without an explicit
 * `crossSubDomainCookies.domain` resolves the domain per request inside
 * BA; it cannot be known here, so those deployments clear without a
 * `Domain` (set `crossSubDomainCookies.domain` to close it).
 *
 * Also covered: the multi-session plugin's per-session cookies
 * (`<session_token>_multi-<token>`, written with the session token's
 * attributes) and the `__Secure-` / plain counterparts of every name
 * (the same attributes, `Secure` forced on a `__Secure-` name).
 */
export function getBetterAuthSessionCookieClearOptions(
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): (name: string) => CookieOptions | undefined {
  const entries = sessionCookieEntries(options, environment)
  const secureDefault = secureCookiesEnabled(options, environment)
  const defaults = options.advanced?.defaultCookieAttributes
  const crossSubDomain = crossSubDomainCookieDomain(options)
  const clearFor = (key: SessionCookieKey | 'dont_remember' | 'account_data'): CookieOptions => {
    const specific = options.advanced?.cookies?.[key]?.attributes
    return {
      secure: (specific?.secure ?? defaults?.secure ?? secureDefault) ? true : undefined,
      domain: specific?.domain ?? defaults?.domain ?? crossSubDomain,
      path: specific?.path ?? defaults?.path,
      partitioned: (specific?.partitioned ?? defaults?.partitioned) === true ? true : undefined,
    }
  }
  const lookup = new Map<string, CookieOptions>(
    entries.map((entry) => [entry.name, clearFor(entry.key)])
  )
  // Logout-only cookies BA writes with their own attributes.
  const sessionDataName = sessionCookieName('session_data', options, environment)
  if (!lookup.has(sessionDataName)) {
    lookup.set(sessionDataName, clearFor('session_data'))
  }
  lookup.set(auxiliaryCookieName('dont_remember', options, environment), clearFor('dont_remember'))
  lookup.set(auxiliaryCookieName('account_data', options, environment), clearFor('account_data'))
  // BA sets `admin_session` with the session token's live attributes
  // (`authCookies.sessionToken.attributes`), not its own per-cookie
  // attributes, so its clearing write must reuse the session token's.
  const sessionTokenName = sessionCookieName('session_token', options, environment)
  const sessionTokenClear = clearFor('session_token')
  lookup.set(auxiliaryCookieName(adminSessionCookieKey, options, environment), sessionTokenClear)
  // The `__Secure-` / plain counterparts (a deployment that switched
  // between http and https left them behind) were written with the same
  // configured attributes; a `__Secure-` name additionally demands
  // `Secure` on every write, the clearing one included.
  for (const [name, clear] of [...lookup]) {
    const toggled = toggledSecureVariant(name)
    if (toggled !== undefined && !lookup.has(toggled)) {
      lookup.set(
        toggled,
        toggled.startsWith(secureCookiePrefix) ? { ...clear, secure: true } : { ...clear }
      )
    }
  }
  const multiSessionPrefix = `${sessionTokenName}_multi-`
  return (name: string): CookieOptions | undefined => {
    // A chunk (`<name>.<n>`, see `betterAuthCookieChunkBase`) is
    // written with its base cookie's attributes; a multi-session
    // cookie with the session token's (BA's multi-session plugin
    // writes it from `authCookies.sessionToken.attributes`).
    const found =
      lookup.get(name) ??
      lookup.get(betterAuthCookieChunkBase(name) ?? '') ??
      (name.startsWith(multiSessionPrefix) ? sessionTokenClear : undefined)
    return found === undefined ? undefined : { ...found }
  }
}

/**
 * The `Domain` BA's `createCookieGetter` puts under every cookie when
 * `crossSubDomainCookies` is enabled: the explicit
 * `crossSubDomainCookies.domain`, otherwise the hostname of a static
 * string `baseURL`. `undefined` when cross-subdomain cookies are off,
 * or when the domain is resolved per request (a dynamic `baseURL`
 * without an explicit domain).
 */
function crossSubDomainCookieDomain(options: BetterAuthCookieOptions): string | undefined {
  const cross = options.advanced?.crossSubDomainCookies
  if (cross?.enabled !== true) {
    return undefined
  }
  if (typeof cross.domain === 'string' && cross.domain !== '') {
    return cross.domain
  }
  if (typeof options.baseURL !== 'string') {
    return undefined
  }
  try {
    return new URL(options.baseURL).hostname
  } catch {
    // BA itself refuses an unparseable baseURL at construction; no
    // domain can be derived from it here.
    return undefined
  }
}

/**
 * The base name of a Better Auth cookie chunk, or `undefined` when the
 * name is not a chunk name. BA's chunking session/account stores split
 * an oversized cookie (cookie-cache `session_data`, `account_data`)
 * into `<name>.0` … `<name>.<n>`; the index must be a non-negative
 * safe integer in canonical decimal form, mirroring BA's own
 * `parseCookieChunkIndex`.
 */
export function betterAuthCookieChunkBase(name: string): string | undefined {
  const dot = name.lastIndexOf('.')
  if (dot <= 0) {
    return undefined
  }
  const suffix = name.slice(dot + 1)
  const index = Number(suffix)
  if (!Number.isSafeInteger(index) || index < 0 || String(index) !== suffix) {
    return undefined
  }
  return name.slice(0, dot)
}

/**
 * The presented chunks (`<base>.<n>`) of the given cookie names on one
 * request's Cookie header names. Chunk names exist only per request —
 * their count follows the payload size — so no static logout list can
 * hold them; the port enumerates them from the request at logout.
 * Names only: values are never read.
 */
export function presentedBetterAuthCookieChunks(
  presentedNames: Iterable<string>,
  bases: readonly string[]
): readonly string[] {
  const chunked = new Set(bases)
  const names: string[] = []
  for (const name of presentedNames) {
    const base = betterAuthCookieChunkBase(name)
    if (base !== undefined && chunked.has(base)) {
      names.push(name)
    }
  }
  return names
}
