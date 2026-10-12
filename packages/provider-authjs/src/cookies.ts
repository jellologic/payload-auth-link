import {
  resolveSecureCookies,
  secureCookiePrefix,
  type CookieOptions,
  type SecureCookieEnvironment,
} from '@payload-auth-link/core'
import type { CookieOption } from '@auth/core/types'

// The core value import above is Edge-safe: `secureCookiePrefix` and
// `resolveSecureCookies` are a const and a pure function with no
// framework or Node imports, and tree-shaken bundlers drop the rest of
// the core barrel from the `cookies` subpath.

/** The Auth.js options that influence cookie names. */
export type AuthJsCookieOptions = {
  /** Mirrors `useSecureCookies`. Defaults to the shared rule below. */
  readonly useSecureCookies?: boolean | undefined
  /**
   * Canonical site origin, used for the secure-cookie default (https →
   * secure + `__Secure-` prefix) via the shared production-secure rule.
   * Auth.js derives the protocol per request (`useSecureCookies ??
   * protocol === 'https:'`); pass the canonical origin so middleware and
   * logout agree with it. Production deployments must set a canonical
   * https origin here: without one the rule falls back to `NODE_ENV`
   * detection, which matches Auth.js on https deployments but fails
   * closed (session detection misses) on http ones.
   */
  readonly baseURL?: string | undefined
  /** Mirrors `cookies.sessionToken.name`. Defaults to the Auth.js default. */
  readonly sessionTokenName?: string | undefined
  /**
   * Mirrors `cookies.sessionToken.options` (Auth.js `SerializeOptions`).
   * Only overwrite-relevant attributes (`secure`, `domain`, `path`,
   * `partitioned`) are read, for logout clearing — `sameSite` and
   * `httpOnly` never affect overwrite matching.
   */
  readonly sessionTokenOptions?: Partial<CookieOption['options']> | undefined
  /**
   * Chunk slots after the base name (`.0`, `.1`, …). Defaults to 3
   * (~12k of token). Raise it when custom claims push JWTs past that;
   * the engine fail-fasts nonsense, this pure function floors and
   * clamps at zero instead.
   */
  readonly chunkSlots?: number | undefined
}

/**
 * Session cookie names for an Auth.js instance: the session-token cookie
 * plus its chunk slots. Auth.js chunks JWTs over ~4k across `name.0`,
 * `name.1`, … and reads them back joined; presence of any slot signals
 * a session for middleware fast-paths, and logout expires all of them.
 * The default three slots cover tokens up to ~12k (measured credentials
 * JWTs are ~550 bytes); raise `chunkSlots` when custom claims push past
 * that. Tokens beyond even the raised slots need Auth.js's own signout
 * action, which clears arbitrary chunks from the request cookies.
 *
 * Only session-indicating cookies are listed: csrf/callback-url cookies
 * exist pre-login and must never count as a session.
 */
function secureByDefault(
  options: AuthJsCookieOptions,
  environment?: SecureCookieEnvironment
): boolean {
  return resolveSecureCookies(
    { useSecureCookies: options.useSecureCookies, baseURL: options.baseURL },
    // The core rule takes no globals: the adapter injects the live env
    // (inlined by Edge bundlers).
    { nodeEnv: environment?.nodeEnv ?? process.env.NODE_ENV }
  )
}

export function getAuthJsSessionCookieNames(
  options: AuthJsCookieOptions,
  environment?: SecureCookieEnvironment
): readonly string[] {
  const secure = secureByDefault(options, environment)
  const base = options.sessionTokenName ?? `${secure ? secureCookiePrefix : ''}authjs.session-token`
  const slots = Math.max(0, Math.floor(options.chunkSlots ?? 3))
  return [base, ...Array.from({ length: slots }, (_, slot) => `${base}.${slot}`)]
}

/**
 * Logout clearing lookup: the live overwrite attributes for each session
 * cookie (base plus chunk slots share them). `secure` defaults to the
 * same rule as the names, so a custom `sessionTokenName` without the
 * `__Secure-` prefix still clears with `Secure` when Auth.js sets it —
 * prefix inference alone would miss that combination. Unknown names yield
 * `undefined` so the caller falls back to `expiringCookieOptions`.
 */
export function getAuthJsSessionCookieClearOptions(
  options: AuthJsCookieOptions,
  environment?: SecureCookieEnvironment
): (name: string) => CookieOptions | undefined {
  const names = new Set(getAuthJsSessionCookieNames(options, environment))
  const overrides = options.sessionTokenOptions
  const attrs: CookieOptions = {
    secure: (overrides?.secure ?? secureByDefault(options, environment)) ? true : undefined,
    domain: overrides?.domain,
    path: overrides?.path,
    partitioned: overrides?.partitioned === true ? true : undefined,
  }
  return (name: string): CookieOptions | undefined => (names.has(name) ? { ...attrs } : undefined)
}
