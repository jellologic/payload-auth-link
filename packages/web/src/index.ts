/**
 * Framework-free web-adapter toolkit: auth route handlers, server-side
 * session verification, server authorization, and redirect safety. No
 * framework imports — framework adapters (`next`, `tanstack-start`)
 * build on this (see DNA §3).
 */
export const packageName = '@payload-auth-link/web'

export { requireRoles, requireSessionUser } from './authz.js'
export type { RequireRolesOptions } from './authz.js'
export { createRouteHandlers } from './handlers.js'
export type { RouteHandler, RouteHandlersOptions } from './handlers.js'
export { decideAuthRedirect, safeRedirectPath } from './redirect.js'
export type { AuthRedirectOptions } from './redirect.js'
export { createSessionVerifier, resolveSessionUrl } from './verify.js'
export type { SessionVerifier, SessionVerifierOptions } from './verify.js'
