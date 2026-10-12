import type { SessionUser } from '@payload-auth-link/core'
import type { SessionVerifier } from '@payload-auth-link/web'

/**
 * Read the session user inside a server function, loader, or route
 * handler: forwards the request to the shared verifier (fails closed
 * to `null`). Pair with Start's `getRequest()`:
 *
 * ```ts
 * // lib/session.ts
 * import { createServerFn } from '@tanstack/react-start'
 * import { getRequest } from '@tanstack/react-start/server'
 * import { getSessionUserFromRequest } from '@payload-auth-link/tanstack-start'
 *
 * export const getSessionUser = createServerFn({ method: 'GET' }).handler(() =>
 *   getSessionUserFromRequest(getRequest(), verifySession)
 * )
 * ```
 *
 * Deliberately a helper, not a pre-built server function: the app's own
 * `createServerFn` call stays in app code where the Start vite plugin
 * transforms it, with no library-transform magic to go stale.
 */
export async function getSessionUserFromRequest(
  request: Request,
  verify: SessionVerifier
): Promise<SessionUser | null> {
  return verify(request.headers)
}
