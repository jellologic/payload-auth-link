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
 * `admin_session` (above) and `dont_remember` (set on a sign-in
 * without "remember me"; BA's own sign-out deletes it).
 */
const auxiliaryCookieKeys = [adminSessionCookieKey, 'dont_remember'] as const
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
 * - the cookie-cache `session_data`, even when the cache is disabled
 *   now — it may have been enabled when the cookie was set;
 * - the `__Secure-` / plain counterpart of every session and logout
 *   name, so a deployment that switched between http and https (or
 *   toggled `useSecureCookies`) leaves no residue under the other
 *   name.
 *
 * Expired unconditionally — a cookie that was never set makes its
 * clearing write a no-op.
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
 * Limitation: `crossSubDomainCookies` derives the cookie domain from the
 * base URL inside BA; that derivation is not mirrored here, so
 * cross-subdomain deployments should sign out through BA's own sign-out
 * for full cookie clearing. Server-side revocation still applies, so any
 * surviving cookie is dead — the plugin fails closed on it.
 */
export function getBetterAuthSessionCookieClearOptions(
  options: BetterAuthCookieOptions,
  environment?: SecureCookieEnvironment
): (name: string) => CookieOptions | undefined {
  const entries = sessionCookieEntries(options, environment)
  const secureDefault = secureCookiesEnabled(options, environment)
  const defaults = options.advanced?.defaultCookieAttributes
  const lookup = new Map<string, CookieOptions>(
    entries.map((entry) => {
      const specific = options.advanced?.cookies?.[entry.key]?.attributes
      return [
        entry.name,
        {
          secure: (specific?.secure ?? defaults?.secure ?? secureDefault) ? true : undefined,
          domain: specific?.domain ?? defaults?.domain,
          path: specific?.path ?? defaults?.path,
          partitioned: (specific?.partitioned ?? defaults?.partitioned) === true ? true : undefined,
        },
      ]
    })
  )
  const clearFor = (key: SessionCookieKey | 'dont_remember'): CookieOptions => {
    const specific = options.advanced?.cookies?.[key]?.attributes
    return {
      secure: (specific?.secure ?? defaults?.secure ?? secureDefault) ? true : undefined,
      domain: specific?.domain ?? defaults?.domain,
      path: specific?.path ?? defaults?.path,
      partitioned: (specific?.partitioned ?? defaults?.partitioned) === true ? true : undefined,
    }
  }
  // Logout-only cookies BA writes with their own attributes.
  const sessionDataName = sessionCookieName('session_data', options, environment)
  if (!lookup.has(sessionDataName)) {
    lookup.set(sessionDataName, clearFor('session_data'))
  }
  lookup.set(auxiliaryCookieName('dont_remember', options, environment), clearFor('dont_remember'))
  // BA sets `admin_session` with the session token's live attributes
  // (`authCookies.sessionToken.attributes`), not its own per-cookie
  // attributes, so its clearing write must reuse the session token's.
  const sessionTokenEntry = entries.find((entry) => entry.key === 'session_token')
  const sessionTokenClear =
    sessionTokenEntry === undefined ? undefined : lookup.get(sessionTokenEntry.name)
  if (sessionTokenClear !== undefined) {
    lookup.set(auxiliaryCookieName(adminSessionCookieKey, options, environment), sessionTokenClear)
  }
  return (name: string): CookieOptions | undefined => {
    const found = lookup.get(name)
    return found === undefined ? undefined : { ...found }
  }
}
