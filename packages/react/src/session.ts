import {
  csrfHeaderName,
  defaultSessionEndpointPath,
  isRecord,
  parseSessionGuest,
  parseSessionResponse,
  parseSessionUser,
  type HttpFetch,
  type SessionGuest,
  type SessionUser,
} from '@payload-auth-link/core'

/**
 * Read the current session user from the plugin's session endpoint
 * (`{ user }` envelope). Fails closed: transport errors, non-2xx
 * statuses, invalid JSON, and malformed envelopes all yield `null`,
 * never an exception and never a partial user.
 */
export async function fetchSessionUser(
  sessionEndpoint: string = defaultSessionEndpointPath,
  fetchImpl: HttpFetch = fetch
): Promise<SessionUser | null> {
  let response: Response
  try {
    response = await fetchImpl(sessionEndpoint, {
      method: 'GET',
      credentials: 'same-origin',
      // Belt and suspenders with the endpoint's `Cache-Control:
      // no-store`: never serve this read from any cache.
      cache: 'no-store',
      headers: { accept: 'application/json' },
    })
  } catch {
    return null
  }
  return parseSessionResponse(response)
}

/** Both halves of one session-endpoint read (CAP-10). */
export type SessionSnapshot = {
  readonly user: SessionUser | null
  readonly guest: SessionGuest | null
}

/**
 * Read user AND guest from one session-endpoint response. The body
 * is parsed exactly once; a guest body yields `user: null` plus the
 * guest, a user body the reverse. Fails closed like
 * {@link fetchSessionUser}; an aborted `signal` reads as empty.
 */
export async function fetchSession(
  sessionEndpoint: string = defaultSessionEndpointPath,
  fetchImpl: HttpFetch = fetch,
  signal?: AbortSignal
): Promise<SessionSnapshot> {
  const empty: SessionSnapshot = { user: null, guest: null }
  let response: Response
  try {
    response = await fetchImpl(sessionEndpoint, {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { accept: 'application/json' },
      ...(signal === undefined ? {} : { signal }),
    })
  } catch {
    return empty
  }
  if (!response.ok) {
    return empty
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return empty
  }
  if (!isRecord(body)) {
    return empty
  }
  return {
    user: parseSessionUser(body.user),
    guest: body.user === null ? parseSessionGuest(body.guest) : null,
  }
}

/**
 * Revoke the current session through the plugin's session endpoint.
 * Sends the CSRF header the endpoint requires. Returns `true` when the
 * session is gone afterwards: `2xx`, or `401` (already signed out —
 * logout is idempotent). Transport errors and other statuses return
 * `false` so the caller can report instead of lying.
 */
export async function revokeSession(
  sessionEndpoint: string = defaultSessionEndpointPath,
  fetchImpl: HttpFetch = fetch
): Promise<boolean> {
  let response: Response
  try {
    response = await fetchImpl(sessionEndpoint, {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: { [csrfHeaderName]: '1' },
    })
  } catch {
    return false
  }
  return response.ok || response.status === 401
}
