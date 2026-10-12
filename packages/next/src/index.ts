/**
 * Next.js adapter: Edge middleware, client refresh, and the
 * server→client provider bridge. The framework-free surface (route
 * handlers, session verification, authorization, redirect safety)
 * lives in `@payload-auth-link/web` and is re-exported here, so
 * existing imports keep working. This is a Next-only package — see
 * DNA §3.
 */
export const packageName = '@payload-auth-link/next'

export { useAuthLinkRefresh } from './client.js'
export { createAuthMiddleware } from './middleware.js'
export type { AuthMiddlewareOptions } from './middleware.js'
export { AuthLinkServerProvider } from './server-provider.js'
export type { AuthLinkServerProviderProps } from './server-provider.js'
export {
  createRouteHandlers,
  createSessionVerifier,
  decideAuthRedirect,
  requireRoles,
  requireSessionUser,
  resolveSessionUrl,
  safeRedirectPath,
} from '@payload-auth-link/web'
export type {
  AuthRedirectOptions,
  RequireRolesOptions,
  RouteHandler,
  RouteHandlersOptions,
  SessionVerifier,
  SessionVerifierOptions,
} from '@payload-auth-link/web'
