import {
  csrfHeaderName,
  RepositoryError,
  SessionExpiredError,
  type LoggerPort,
  type SessionInvalidError,
} from '@payload-auth-link/core'

export { csrfHeaderName }

/**
 * Loud logging for session verification failures. Storage outages are
 * errors with their cause; dead tokens are warnings. Call before
 * returning `{ user: null }` / 401 so every denial is traceable.
 */
export function logVerifyFailure(
  logger: LoggerPort,
  scope: string,
  error: SessionInvalidError | SessionExpiredError | RepositoryError
): void {
  if (error instanceof RepositoryError) {
    logger.error(`${scope} verification failed: storage error`, { cause: error.cause ?? error })
    return
  }
  if (error instanceof SessionExpiredError) {
    logger.warn(`${scope} verification failed: session expired`)
    return
  }
  logger.warn(`${scope} verification failed: invalid session`)
}

/** Strict same-origin comparison against `baseUrl`. Never throws. */
export function isSameOrigin(value: string, baseUrl: string): boolean {
  let candidate: URL
  let base: URL
  try {
    candidate = new URL(value)
    base = new URL(baseUrl)
  } catch {
    return false
  }
  return candidate.origin === base.origin
}

/**
 * CSRF proof for state-changing endpoints: a matching `Origin` header or the
 * custom header. Requests with neither (plain cross-site forms, blind curl)
 * fail closed.
 */
export function passesCsrf(headers: Headers, baseUrl: string): boolean {
  if (headers.get(csrfHeaderName) === '1') {
    return true
  }
  const origin = headers.get('origin')
  if (!origin) {
    return false
  }
  return isSameOrigin(origin, baseUrl)
}

/**
 * JSON envelope for endpoint responses. Session state must never sit in
 * any cache (browser, proxy, or framework): every response carries
 * `no-store`, including errors — a cached 401 would pin a signed-out
 * user, a cached 200 a signed-in one.
 */
export function jsonResponse(data: unknown, status: number): Response {
  const response = Response.json(data, { status })
  response.headers.set('Cache-Control', 'no-store')
  return response
}

/** 401 envelope; the detail never leaks which check failed. */
export function unauthorized(detail = 'authentication required'): Response {
  return jsonResponse({ error: detail }, 401)
}

/** 403 envelope for authenticated-but-denied requests. */
export function forbidden(detail = 'forbidden'): Response {
  return jsonResponse({ error: detail }, 403)
}
