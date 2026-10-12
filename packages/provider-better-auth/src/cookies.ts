import {
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
  const prefix = options.advanced?.cookiePrefix || defaultCookiePrefix
  const secure = secureCookiesEnabled(options, environment) ? secureCookiePrefix : ''
  const nameOf = (cookie: SessionCookieKey): string =>
    `${secure}${options.advanced?.cookies?.[cookie]?.name || `${prefix}.${cookie}`}`
  const entries: Array<{ readonly key: SessionCookieKey; readonly name: string }> = [
    { key: 'session_token', name: nameOf('session_token') },
  ]
  if (options.session?.cookieCache?.enabled === true) {
    entries.push({ key: 'session_data', name: nameOf('session_data') })
  }
  return entries
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
  return (name: string): CookieOptions | undefined => {
    const found = lookup.get(name)
    return found === undefined ? undefined : { ...found }
  }
}
