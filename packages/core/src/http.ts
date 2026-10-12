import { parseEmail } from './email.js'
import { InvalidConfigError } from './errors.js'
import { isNonEmptyString, isRecord } from './guards.js'
import { parseRole } from './roles.js'

/**
 * Custom CSRF header. A cross-site page cannot set it without a preflight,
 * so its presence proves a same-origin (or deliberate non-browser) caller.
 * UI adapters always send it with the value `1` on state-changing requests.
 */
export const csrfHeaderName = 'x-auth-link-csrf'

/**
 * Default plugin session endpoint path. Payload serves custom endpoints
 * under `/api`; builders who customize `routes.api` override the endpoint
 * in the UI adapters instead of this constant.
 */
export const defaultSessionEndpointPath = '/api/auth-link/session'

/**
 * Injectible `fetch` shape. UI adapters default to the global `fetch`;
 * tests inject stubs. Same signature as `fetch` restricted to string URLs.
 */
export type HttpFetch = (input: string, init?: RequestInit) => Promise<Response>

/**
 * Validate a configured origin. Returns it unchanged when it is an
 * absolute http(s) URL; throws `InvalidConfigError` otherwise. Call at
 * wiring time so a malformed base URL fails the build, never a request
 * (where `new URL` would throw a bare `TypeError` instead).
 */
export function normalizeBaseUrl(baseUrl: string): string {
  let parsed: URL
  try {
    parsed = new URL(baseUrl)
  } catch {
    throw new InvalidConfigError(
      `baseUrl must be an absolute http(s) URL, got ${JSON.stringify(baseUrl)}`
    )
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new InvalidConfigError(
      `baseUrl must be an absolute http(s) URL, got ${JSON.stringify(baseUrl)}`
    )
  }
  return baseUrl
}

/** Origin resolution: configured base URL plus the dev-only host fallback. */
export type OriginResolutionInput = {
  /** Validated configured origin; wins whenever set. */
  readonly baseUrl?: string | undefined
  /** Request headers, for the host fallback only. */
  readonly headers: Headers
  /**
   * Whether the request-host fallback is allowed. Host headers are
   * client-spoofable, so production session reads (which forward
   * cookies to the resolved origin) must pass `false`; local
   * development passes `true`.
   */
  readonly allowHostFallback: boolean
}

/**
 * Single origin resolver behind every server-side session read
 * (`@payload-auth-link/web` verifier, Auth.js engine). The configured
 * base URL wins; without it, the request host is used only when
 * `allowHostFallback` is set. Throws `InvalidConfigError` when no
 * origin can be resolved — a wiring bug, fail loud rather than
 * fetching a nonsense URL.
 */
export function resolveOrigin(input: OriginResolutionInput): string {
  if (input.baseUrl !== undefined) {
    return normalizeBaseUrl(input.baseUrl)
  }
  if (!input.allowHostFallback) {
    throw new InvalidConfigError(
      'cannot resolve origin: no baseUrl configured and the request-host fallback is disabled'
    )
  }
  const host = input.headers.get('x-forwarded-host') ?? input.headers.get('host')
  if (!host) {
    throw new InvalidConfigError('cannot resolve origin: no host header and no baseUrl')
  }
  const proto = input.headers.get('x-forwarded-proto') ?? 'http'
  return `${proto}://${host}`
}

/**
 * The session user: what the plugin's session endpoint returns inside its
 * `{ user }` envelope, and what the UI adapters hydrate from. Plain JSON —
 * roles are the wire form of `Role`, re-validated on parse.
 */
export type SessionUser = {
  readonly id: string
  readonly collection: string
  readonly email: string
  readonly roles: readonly string[]
}

/**
 * Narrow unknown JSON to a `SessionUser`. Fails closed (`null`) on any
 * deviation: the server writes this shape from validated domain types, so
 * anything else is version skew or tampering, never a partial session.
 */
export function parseSessionUser(value: unknown): SessionUser | null {
  if (!isRecord(value)) {
    return null
  }
  if (!isNonEmptyString(value.id) || !isNonEmptyString(value.collection)) {
    return null
  }
  const email = parseEmail(value.email)
  if (email.isErr()) {
    return null
  }
  if (!Array.isArray(value.roles)) {
    return null
  }
  const roles: string[] = []
  for (const role of value.roles) {
    const parsed = parseRole(role)
    if (parsed.isErr()) {
      return null
    }
    roles.push(parsed.value)
  }
  return { id: value.id, collection: value.collection, email: email.value, roles }
}

/**
 * Parse a session-endpoint `Response` through its `{ user }` envelope.
 * Fails closed (`null`) on non-2xx statuses, unreadable JSON, non-record
 * bodies, and malformed users — the single envelope parser shared by
 * the client reader (`react`) and the server verifier (`web`).
 */
export async function parseSessionResponse(
  response: Pick<Response, 'ok' | 'json'>
): Promise<SessionUser | null> {
  if (!response.ok) {
    return null
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return null
  }
  if (!isRecord(body)) {
    return null
  }
  return parseSessionUser(body.user)
}
