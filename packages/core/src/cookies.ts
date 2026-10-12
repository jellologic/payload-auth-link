import type { CookieOptions, SameSite } from './ports.js'

function assertCookieName(name: string): void {
  if (!/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(name)) {
    throw new Error(`Invalid cookie name: ${name}`)
  }
}

/**
 * Serialize one `Set-Cookie` header value. Pure and framework-free;
 * `CookiePort` adapters use this — never hand-rolled cookie strings.
 */
export function serializeCookie(name: string, value: string, options?: CookieOptions): string {
  assertCookieName(name)
  const parts = [`${name}=${encodeURIComponent(value)}`]
  if (options?.maxAge !== undefined) {
    parts.push(`Max-Age=${Math.trunc(options.maxAge)}`)
  }
  if (options?.domain !== undefined) {
    parts.push(`Domain=${options.domain}`)
  }
  if (options?.path !== undefined) {
    parts.push(`Path=${options.path}`)
  }
  if (options?.httpOnly === true) {
    parts.push('HttpOnly')
  }
  if (options?.secure === true) {
    parts.push('Secure')
  }
  const sameSite: SameSite | undefined = options?.sameSite
  if (sameSite !== undefined) {
    const rendered = sameSite === 'lax' ? 'Lax' : sameSite === 'strict' ? 'Strict' : 'None'
    parts.push(`SameSite=${rendered}`)
  }
  if (options?.partitioned === true) {
    parts.push('Partitioned')
  }
  return parts.join('; ')
}

/**
 * RFC 6265bis `__Secure-` prefix: setting or clearing such a cookie
 * requires the `Secure` attribute, or the browser rejects the write.
 */
export const secureCookiePrefix = '__Secure-'

/**
 * Inputs to the shared production-secure rule. Every provider's
 * cookie-name derivation funnels through {@link resolveSecureCookies}
 * with these three inputs so secure-cookie behavior cannot drift
 * between providers.
 */
export type SecureCookieRuleInput = {
  /** Explicit builder flag; wins over every other input. */
  readonly useSecureCookies?: boolean | undefined
  /** Configured site origin; an https origin means secure cookies. */
  readonly baseURL?: string | undefined
  /**
   * Better Auth object-form `baseURL` protocol (`'https'` / `'http'`),
   * which that SDK reads at runtime ahead of the string check. Providers
   * whose SDK has no object form leave this unset.
   */
  readonly dynamicProtocol?: string | undefined
}

/** Injectable environment for the production fallback below. */
export type SecureCookieEnvironment = {
  readonly nodeEnv?: string | undefined
}

/**
 * One production-secure rule shared by every provider: an explicit
 * `useSecureCookies` wins, then the configured origin (https → secure),
 * then `NODE_ENV=production`. Pure and Edge-safe — no imports, no
 * globals: callers inject the environment (adapters read the live
 * `NODE_ENV`; an absent environment reads as non-production).
 *
 * Production deployments must set a canonical https `baseURL`: it is the
 * only input on which both SDKs and the session layer's origin anchoring
 * agree. Without it, production falls back to `NODE_ENV` detection, which
 * matches SDK behavior on https deployments but fails closed (Auth.js
 * session detection misses) on http ones.
 */
export function resolveSecureCookies(
  input: SecureCookieRuleInput,
  environment?: SecureCookieEnvironment
): boolean {
  if (input.useSecureCookies !== undefined) {
    return input.useSecureCookies
  }
  if (input.dynamicProtocol === 'https') {
    return true
  }
  if (input.dynamicProtocol === 'http') {
    return false
  }
  if (input.baseURL !== undefined) {
    return input.baseURL.startsWith('https://')
  }
  return environment?.nodeEnv === 'production'
}

/**
 * RFC 6265bis `__Host-` prefix: requires `Secure`, `Path=/`, and no
 * `Domain` on every write, including the clearing write.
 */
export const hostCookiePrefix = '__Host-'

/**
 * Clearing attributes for a session cookie known by name only: `Max-Age=0`
 * at `Path=/`, plus `Secure` when the name carries a prefix that demands
 * it. Providers that know their cookies' real attributes (custom names,
 * custom domains) report them via
 * `IdentityProviderPort.sessionCookieClearOptions` instead — this is the
 * fallback for providers that predate that hook.
 */
export function expiringCookieOptions(name: string): CookieOptions {
  const prefixed = name.startsWith(secureCookiePrefix) || name.startsWith(hostCookiePrefix)
  return prefixed ? { maxAge: 0, path: '/', secure: true } : { maxAge: 0, path: '/' }
}

/** Parse a `Cookie` request header into name/value pairs. */
export function parseCookieHeader(header: string | null): ReadonlyMap<string, string> {
  const pairs = new Map<string, string>()
  if (header === null || header === '') {
    return pairs
  }
  for (const part of header.split(';')) {
    const separator = part.indexOf('=')
    if (separator <= 0) {
      continue
    }
    const name = part.slice(0, separator).trim()
    const rawValue = part.slice(separator + 1).trim()
    if (name === '') {
      continue
    }
    try {
      pairs.set(name, decodeURIComponent(rawValue))
    } catch {
      pairs.set(name, rawValue)
    }
  }
  return pairs
}
