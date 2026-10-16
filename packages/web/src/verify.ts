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
 * The narrowed `SessionUser` carries the endpoint's optional PORT-4
 * facts (`assurance`, `actor`, `organizationId`) when the server sent
 * them; absent or `'unknown'` assurance never proves a method or MFA.
 */
export type SessionVerifier = (headers: Headers) => Promise<SessionUser | null>

/** Hosts the development host fallback may resolve to by default. */
export const defaultDevelopmentHosts: readonly string[] = ['localhost', '127.0.0.1', '[::1]']

/** Default verifier fetch timeout, in milliseconds. */
export const defaultSessionVerifierTimeoutMs = 5000

/** Full server-side session validation wiring. */
export type SessionVerifierOptions = {
  /**
   * Session endpoint path (starting with a single `/`) or absolute
   * http(s) URL. Defaults to the plugin's. Protocol-relative values
   * (`//host/x`) and other schemes throw `InvalidConfigError` at
   * construction.
   */
  readonly sessionEndpoint?: string | undefined
  /**
   * Origin for relative endpoints (e.g. `https://app.example.com`).
   * Required whenever `NODE_ENV` is not exactly `'development'`
   * (unset, `'production'`, `'test'`, `'staging'`, …): construction
   * throws `InvalidConfigError` without it. When omitted in
   * development, the origin is derived from the request's `Host`
   * header — client-controlled, and the session cookie is forwarded
   * to it — so that fallback is restricted by `trustProxy` and
   * `allowedDevelopmentHosts`.
   */
  readonly baseUrl?: string | undefined
  /**
   * Development host fallback only: honor `X-Forwarded-Host` /
   * `X-Forwarded-Proto`. Default `false` — any client can send those
   * headers. Enable only behind a local proxy that overwrites them.
   */
  readonly trustProxy?: boolean | undefined
  /**
   * Development host fallback only: hostnames (no port; IPv6 in
   * brackets) the request host may name. Default
   * `['localhost', '127.0.0.1', '[::1]']`. Any other host makes the
   * request fail closed (`null`, reported through `onError`).
   */
  readonly allowedDevelopmentHosts?: readonly string[] | undefined
  /**
   * Abort the session fetch after this many milliseconds (default
   * 5000). A timeout fails closed (`null`) and is reported through
   * `onError`.
   */
  readonly timeoutMs?: number | undefined
  /** Injectible fetch. Defaults to the global `fetch`. */
  readonly fetchImpl?: HttpFetch | undefined
  /**
   * Called with transport errors, timeouts, and request-time origin
   * rejections — all of which otherwise fail closed to `null`.
   */
  readonly onError?: ((error: unknown) => void) | undefined
  /**
   * Injectable environment for the development gate. Defaults to
   * `process.env` — tests inject `{ nodeEnv: 'development' }` instead
   * of mutating the environment.
   */
  readonly environment?: { readonly nodeEnv?: string | undefined } | undefined
}

/** Host-fallback policy for `resolveSessionUrl`. */
export type SessionUrlHostPolicy = {
  /** Honor `X-Forwarded-*` headers. Default `false`. */
  readonly trustProxy?: boolean | undefined
  /** Allowed hostnames. Default `defaultDevelopmentHosts`. */
  readonly allowedHosts?: readonly string[] | undefined
}

/**
 * Validate a session endpoint: an absolute http(s) URL, or a path
 * starting with exactly one `/`. Protocol-relative (`//host/x`,
 * `/\host`) and other-scheme values would resolve off-origin, so they
 * throw `InvalidConfigError`.
 */
export function validateSessionEndpoint(sessionEndpoint: string): string {
  if (/^https?:\/\//i.test(sessionEndpoint)) {
    return normalizeBaseUrl(sessionEndpoint)
  }
  if (!sessionEndpoint.startsWith('/') || /^\/[/\\]/.test(sessionEndpoint)) {
    throw new InvalidConfigError(
      `sessionEndpoint must be an absolute http(s) URL or a path starting with a single "/", got ${JSON.stringify(sessionEndpoint)}`
    )
  }
  return sessionEndpoint
}

/**
 * Resolve a session endpoint to an absolute URL. Absolute endpoints pass
 * through; relative ones resolve against the shared origin resolver
 * (`baseUrl`, else the request host when `allowHostFallback` is set).
 * The `baseUrl` form is the production form (see
 * `SessionVerifierOptions.baseUrl`); the host fallback trusts
 * client-controlled headers and is local-development only, so it
 * ignores `X-Forwarded-*` unless `hostPolicy.trustProxy` is set and
 * accepts only `hostPolicy.allowedHosts` (default: loopback names).
 * Throws `InvalidConfigError` when no acceptable origin can be resolved
 * or the endpoint is protocol-relative — fail loud rather than
 * fetching a nonsense URL.
 */
export function resolveSessionUrl(
  headers: Headers,
  sessionEndpoint: string = defaultSessionEndpointPath,
  baseUrl?: string,
  allowHostFallback = false,
  hostPolicy: SessionUrlHostPolicy = {}
): string {
  const endpoint = validateSessionEndpoint(sessionEndpoint)
  if (/^https?:\/\//i.test(endpoint)) {
    return endpoint
  }
  const origin = resolveOrigin({
    baseUrl,
    headers,
    allowHostFallback,
    trustProxy: hostPolicy.trustProxy === true,
    allowedHosts: hostPolicy.allowedHosts ?? defaultDevelopmentHosts,
  })
  return new URL(endpoint, origin).toString()
}

/**
 * Full server-side session validation for Node (server components, route
 * handlers): forwards the request cookies to the plugin's session
 * endpoint and narrows the answer. Fails closed — missing cookies,
 * non-2xx, invalid JSON, transport errors, timeouts, and rejected
 * request origins all yield `null`. The fetch is never cached
 * (`no-store`): a revoked session must read as revoked on the very
 * next request.
 *
 * Without `baseUrl`, construction throws unless `NODE_ENV` is exactly
 * `'development'` (an explicit allowlist, matching `authLinkServer`'s
 * `'dev-only'` gate).
 */
export function createSessionVerifier(options: SessionVerifierOptions = {}): SessionVerifier {
  const {
    sessionEndpoint = defaultSessionEndpointPath,
    baseUrl,
    trustProxy = false,
    allowedDevelopmentHosts = defaultDevelopmentHosts,
    timeoutMs = defaultSessionVerifierTimeoutMs,
    fetchImpl = fetch,
    onError,
    environment,
  } = options
  // Fail fast at wiring: a malformed base URL or endpoint must never
  // reach a request (where `new URL` would throw a bare `TypeError`, or
  // a protocol-relative endpoint would silently leave the origin).
  const normalizedBaseUrl = baseUrl === undefined ? undefined : normalizeBaseUrl(baseUrl)
  const endpoint = validateSessionEndpoint(sessionEndpoint)
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new InvalidConfigError(
      `createSessionVerifier timeoutMs must be a positive number, got ${String(timeoutMs)}`
    )
  }
  // Development gate (explicit allowlist): without a configured origin
  // the verifier forwards session cookies to a client-influenced host.
  // Anything but NODE_ENV=development — unset, test, staging, preview,
  // production — refuses to construct.
  const nodeEnv = environment === undefined ? process.env.NODE_ENV : environment.nodeEnv
  const allowHostFallback = nodeEnv === 'development'
  const absoluteEndpoint = /^https?:\/\//i.test(endpoint)
  if (normalizedBaseUrl === undefined && !absoluteEndpoint && !allowHostFallback) {
    throw new InvalidConfigError(
      `createSessionVerifier requires baseUrl unless NODE_ENV=development (got ${JSON.stringify(nodeEnv ?? '')}): the request-host fallback would forward session cookies to a client-spoofable origin`
    )
  }
  const hostPolicy: SessionUrlHostPolicy = { trustProxy, allowedHosts: allowedDevelopmentHosts }
  return async (headers: Headers): Promise<SessionUser | null> => {
    const cookie = headers.get('cookie')
    if (!cookie) {
      return null
    }
    let response: Response
    try {
      const url = resolveSessionUrl(
        headers,
        endpoint,
        normalizedBaseUrl,
        allowHostFallback,
        hostPolicy
      )
      response = await fetchImpl(url, {
        headers: { cookie, accept: 'application/json' },
        cache: 'no-store',
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      })
    } catch (error) {
      onError?.(error)
      return null
    }
    // Body read failures (including a timeout firing mid-body) fail
    // closed inside the parser.
    return parseSessionResponse(response)
  }
}
