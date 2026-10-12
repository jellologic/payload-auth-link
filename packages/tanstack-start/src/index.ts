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
// The whole framework-free web surface, in ONE statement shared verbatim
// by both adapters: a new web export reaches every adapter automatically
// and the adapters cannot drift apart (barrel tests pin the sets). The
// local `packageName` above takes precedence over web's.
export * from '@payload-auth-link/web'
