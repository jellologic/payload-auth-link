/** A framework-agnostic auth request handler. */
export type RouteHandler = (request: Request) => Promise<Response>

/** Error-reporting hook for {@link createRouteHandlers}. */
export type RouteHandlersOptions = {
  /** Called with handler errors (which otherwise become a 500 envelope). */
  readonly onError?: ((error: unknown) => void) | undefined
}

/**
 * Mount any auth request handler (e.g. a provider's `auth.handler`) as
 * Next.js `GET`/`POST` route exports with a uniform error envelope —
 * thrown errors become `{ error }` 500s instead of HTML error pages.
 *
 * ```ts
 * // app/api/auth/[...all]/route.ts
 * import { createRouteHandlers } from '@payload-auth-link/next'
 * import { auth } from '@/lib/auth'
 *
 * export const { GET, POST } = createRouteHandlers((request) => auth.handler(request))
 * ```
 */
export function createRouteHandlers(
  handle: RouteHandler,
  options: RouteHandlersOptions = {}
): { readonly GET: RouteHandler; readonly POST: RouteHandler } {
  const run: RouteHandler = async (request: Request): Promise<Response> => {
    try {
      return await handle(request)
    } catch (error) {
      options.onError?.(error)
      return Response.json({ error: 'auth handler failed' }, { status: 500 })
    }
  }
  return { GET: run, POST: run }
}
