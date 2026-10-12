/**
 * TanStack Start adapter: server-route handlers, request middleware,
 * session server-function helpers, route-loader hydration, and the
 * client refresh hook. Framework-free behavior (verification,
 * authorization, redirect safety) lives in `@payload-auth-link/web`.
 * This is the only package that imports `@tanstack/*` — see DNA §3.
 */
export const packageName = '@payload-auth-link/tanstack-start'

export { useAuthLinkRefreshStart } from './client.js'
export { createServerRouteHandlers } from './handlers.js'
export type { ServerRouteContext, ServerRouteHandlersOptions } from './handlers.js'
export { createAuthRequestMiddleware } from './middleware.js'
export type { AuthRequestMiddlewareOptions } from './middleware.js'
export { createSessionLoader } from './loader.js'
export type { SessionLoaderData } from './loader.js'
export { getSessionUserFromRequest } from './server.js'
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
