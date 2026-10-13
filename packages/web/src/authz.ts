import {
  ForbiddenError,
  InvalidConfigError,
  MfaRequiredError,
  mfaSatisfied,
  parseRole,
  SessionInvalidError,
  type SessionUser,
} from '@payload-auth-link/core'
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
 * `onAnonymous`) when there is no valid session. The returned user
 * carries any PORT-4 facts the session endpoint reported
 * (`assurance`, `actor`, `organizationId`) for caller-side policy.
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
  /**
   * Also require MFA proof for this session (CAP-6): an authenticated
   * user holding the roles but lacking `assurance.mfa === true`
   * (`'unknown'` never satisfies) hits `onMfaRequired` (default:
   * throw `MfaRequiredError`, map to 403/step-up). Independent of
   * the plugin's `requireMfaForRoles` projection, which withholds
   * the roles themselves — use either or both.
   */
  readonly requireMfa?: boolean | undefined
  /** Anonymous handler, e.g. `() => redirect('/sign-in')`. */
  readonly onAnonymous?: (() => never) | undefined
  /** Authenticated-but-denied handler, e.g. `() => notFound()`. */
  readonly onDenied?: ((user: SessionUser) => never) | undefined
  /** Authenticated-with-roles-but-no-MFA handler (step-up redirect). */
  readonly onMfaRequired?: ((user: SessionUser) => never) | undefined
}

/**
 * Require an authenticated user holding every listed role. Fails closed:
 * anonymous callers hit `onAnonymous` (default: throw
 * `SessionInvalidError`), authenticated callers missing any role hit
 * `onDenied` (default: throw `ForbiddenError` naming the missing roles).
 *
 * The required roles are validated first, before any session read: an
 * invalid entry (e.g. a typo-cased `'Admin'`, which no canonical role can
 * ever equal) throws `InvalidRoleError`, and an empty list throws
 * `InvalidConfigError` (use `requireSessionUser` for "any signed-in
 * user"). Either would otherwise silently deny everyone or grant everyone.
 */
export async function requireRoles(
  headers: Headers,
  verify: SessionVerifier,
  options: RequireRolesOptions
): Promise<SessionUser> {
  if (options.roles.length === 0) {
    throw new InvalidConfigError('requireRoles needs at least one role')
  }
  for (const role of options.roles) {
    const parsed = parseRole(role)
    if (parsed.isErr()) {
      throw parsed.error
    }
  }
  const user = await requireSessionUser(headers, verify, options.onAnonymous)
  const missing = options.roles.filter((role) => !user.roles.includes(role))
  if (missing.length > 0) {
    // When the session endpoint withheld roles for MFA (CAP-6 wire
    // flag), the honest denial is the step-up error, not a flat 403.
    if (user.mfaRequired === true) {
      options.onMfaRequired?.(user)
      throw new MfaRequiredError(`roles withheld pending MFA: ${missing.join(', ')}`)
    }
    options.onDenied?.(user)
    throw new ForbiddenError(`missing roles: ${missing.join(', ')}`)
  }
  if (options.requireMfa === true && !mfaSatisfied(user.assurance)) {
    options.onMfaRequired?.(user)
    throw new MfaRequiredError('this resource requires a multi-factor session')
  }
  return user
}
