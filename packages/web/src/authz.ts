import { ForbiddenError, SessionInvalidError, type SessionUser } from '@payload-auth-link/core'
import type { SessionVerifier } from './verify.js'

/**
 * Server-side authorization for Node (server components, route handlers).
 * This is the enforcement point — unlike `RequireRoles` (which only hides
 * UI), these helpers run before any protected content renders or any
 * protected mutation executes, so denied callers never receive it.
 *
 * Pass live request headers (Next.js `await headers()`) and a verifier
 * from `createSessionVerifier`. By default the helpers throw
 * `SessionInvalidError` (anonymous) and `ForbiddenError` (missing roles);
 * pass Next.js's `redirect()` / `notFound()` as the handlers, or catch in
 * route handlers and map to 401 / 403.
 */

/**
 * Require an authenticated session user. Throws (or delegates to
 * `onAnonymous`) when there is no valid session.
 */
export async function requireSessionUser(
  headers: Headers,
  verify: SessionVerifier,
  onAnonymous?: () => never
): Promise<SessionUser> {
  const user = await verify(headers)
  if (!user) {
    onAnonymous?.()
    throw new SessionInvalidError('authentication required')
  }
  return user
}

/** `requireRoles` wiring: required roles plus denial handlers. */
export type RequireRolesOptions = {
  /** Every listed role is required. */
  readonly roles: readonly string[]
  /** Anonymous handler, e.g. `() => redirect('/sign-in')`. */
  readonly onAnonymous?: (() => never) | undefined
  /** Authenticated-but-denied handler, e.g. `() => notFound()`. */
  readonly onDenied?: ((user: SessionUser) => never) | undefined
}

/**
 * Require an authenticated user holding every listed role. Fails closed:
 * anonymous callers hit `onAnonymous` (default: throw
 * `SessionInvalidError`), authenticated callers missing any role hit
 * `onDenied` (default: throw `ForbiddenError` naming the missing roles).
 */
export async function requireRoles(
  headers: Headers,
  verify: SessionVerifier,
  options: RequireRolesOptions
): Promise<SessionUser> {
  const user = await requireSessionUser(headers, verify, options.onAnonymous)
  const missing = options.roles.filter((role) => !user.roles.includes(role))
  if (missing.length > 0) {
    options.onDenied?.(user)
    throw new ForbiddenError(`missing roles: ${missing.join(', ')}`)
  }
  return user
}
