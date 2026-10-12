import {
  createRouteHandlers,
  type RouteHandler,
  type RouteHandlersOptions,
} from '@payload-auth-link/web'

/** TanStack Start server-route handler context: the incoming request. */
export type ServerRouteContext = {
  readonly request: Request
}

/** Error-reporting hook for {@link createServerRouteHandlers}. */
export type ServerRouteHandlersOptions = RouteHandlersOptions

/**
 * Mount any auth request handler (e.g. a provider's `auth.handler`) as
 * TanStack Start `server.handlers` `GET`/`POST` exports. The envelope is
 * shared with Next (`createRouteHandlers`) — thrown errors become
 * `{ error }` 500s instead of HTML error pages.
 *
 * ```ts
 * // src/app/api.auth.$.ts
 * import { createServerRouteHandlers } from '@payload-auth-link/tanstack-start'
 * import { auth } from '@/lib/auth'
 *
 * export const Route = createFileRoute('/api/auth/$')({
 *   server: { handlers: createServerRouteHandlers((request) => auth.handler(request)) },
 * })
 * ```
 */
export function createServerRouteHandlers(
  handle: RouteHandler,
  options: ServerRouteHandlersOptions = {}
): {
  readonly GET: (context: ServerRouteContext) => Promise<Response>
  readonly POST: (context: ServerRouteContext) => Promise<Response>
} {
  const { GET, POST } = createRouteHandlers(handle, options)
  return {
    GET: ({ request }: ServerRouteContext): Promise<Response> => GET(request),
    POST: ({ request }: ServerRouteContext): Promise<Response> => POST(request),
  }
}
