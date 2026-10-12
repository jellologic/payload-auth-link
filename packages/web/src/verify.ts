import {
  defaultSessionEndpointPath,
  InvalidConfigError,
  normalizeBaseUrl,
  parseSessionResponse,
  resolveOrigin,
  type HttpFetch,
  type SessionUser,
} from '@payload-auth-link/core'

/**
 * Full server-side session validation: forwards request cookies to the
 * plugin session endpoint and narrows the answer. Fails closed (`null`).
 */
export type SessionVerifier = (headers: Headers) => Promise<SessionUser | null>

/** Full server-side session validation wiring. */
export type SessionVerifierOptions = {
  /** Session endpoint path or absolute URL. Defaults to the plugin's. */
  readonly sessionEndpoint?: string | undefined
  /**
   * Origin for relative endpoints (e.g. `https://app.example.com`).
   * Required in production behind a proxy: when omitted, the origin is
   * derived from the request's host headers, which a client can spoof —
   * and the session cookie is forwarded to that origin, so a spoofed
   * host exfiltrates it. The header fallback is a local-development
   * convenience only.
   */
  readonly baseUrl?: string | undefined
  /** Injectible fetch. Defaults to the global `fetch`. */
  readonly fetchImpl?: HttpFetch | undefined
  /** Called with transport errors (which otherwise fail closed to null). */
  readonly onError?: ((error: unknown) => void) | undefined
  /**
   * Injectable environment for the production gate. Defaults to
   * `process.env` — tests inject `{ nodeEnv: 'production' }` instead
   * of mutating the environment.
   */
  readonly environment?: { readonly nodeEnv?: string | undefined } | undefined
}

/**
 * Resolve a session endpoint to an absolute URL. Absolute endpoints pass
 * through; relative ones resolve against the shared origin resolver
 * (`baseUrl`, else the request host when `allowHostFallback` is set).
 * The `baseUrl` form is the production form (see
 * `SessionVerifierOptions.baseUrl`); the host fallback trusts
 * client-controlled headers and is local-development only. Throws
 * `InvalidConfigError` when no origin can be resolved — a wiring bug,
 * fail loud rather than fetching a nonsense URL.
 */
export function resolveSessionUrl(
  headers: Headers,
  sessionEndpoint: string = defaultSessionEndpointPath,
  baseUrl?: string,
  allowHostFallback = true
): string {
  if (/^https?:\/\//.test(sessionEndpoint)) {
    return sessionEndpoint
  }
  return new URL(sessionEndpoint, resolveOrigin({ baseUrl, headers, allowHostFallback })).toString()
}

/**
 * Full server-side session validation for Node (server components, route
 * handlers): forwards the request cookies to the plugin's session
 * endpoint and narrows the answer. Fails closed — missing cookies,
 * non-2xx, invalid JSON, and transport errors all yield `null`. The
 * fetch is never cached (`no-store`): a revoked session must read as
 * revoked on the very next request.
 */
export function createSessionVerifier(options: SessionVerifierOptions = {}): SessionVerifier {
  const {
    sessionEndpoint = defaultSessionEndpointPath,
    baseUrl,
    fetchImpl = fetch,
    onError,
    environment,
  } = options
  // Fail fast at wiring: a malformed base URL must never reach a request
  // (where `new URL` would throw a bare `TypeError` instead).
  const normalizedBaseUrl = baseUrl === undefined ? undefined : normalizeBaseUrl(baseUrl)
  // Production gate: without a configured origin the verifier would
  // forward session cookies to a client-spoofable host. Refuse to
  // construct rather than mint a forgery-capable verifier.
  const allowHostFallback = (environment?.nodeEnv ?? process.env.NODE_ENV ?? '') !== 'production'
  if (normalizedBaseUrl === undefined && !allowHostFallback) {
    throw new InvalidConfigError(
      'createSessionVerifier requires baseUrl in production (NODE_ENV=production): the request-host fallback would forward session cookies to a client-spoofable origin'
    )
  }
  return async (headers: Headers): Promise<SessionUser | null> => {
    const cookie = headers.get('cookie')
    if (!cookie) {
      return null
    }
    let response: Response
    try {
      response = await fetchImpl(
        resolveSessionUrl(headers, sessionEndpoint, normalizedBaseUrl, allowHostFallback),
        {
          headers: { cookie, accept: 'application/json' },
          cache: 'no-store',
        }
      )
    } catch (error) {
      onError?.(error)
      return null
    }
    return parseSessionResponse(response)
  }
}
