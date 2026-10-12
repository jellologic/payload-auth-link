import { decideAuthRedirect, type AuthRedirectOptions } from '@payload-auth-link/web'
import { createMiddleware } from '@tanstack/react-start'

/** Optimistic request-middleware wiring; see {@link createAuthRequestMiddleware}. */
export type AuthRequestMiddlewareOptions = AuthRedirectOptions & {
  /**
   * Bounce `/_serverFn/` RPC through the auth check. Defaults to false:
   * the exemption is built in because bouncing RPC corrupts the
   * server-function protocol (redirect followed with a JSON Accept →
   * Start 406). Set true only if you want the bounce anyway. Server
   * functions authenticate themselves via the shared verifier either
   * way — this flag only controls the optimistic bounce.
   */
  readonly bounceServerFunctions?: boolean | undefined
}

/** Start RPC prefix: exempt from the bounce unless opted out (see above). */
const serverFunctionsPath = /^\/_serverFn(\/|$)/

/**
 * Optimistic auth request middleware: presence of any session cookie
 * lets the request through; absence redirects to sign-in. Optimistic is
 * deliberate — route protection here is UX (bounce obvious anonymous
 * traffic early), never authorization. Real validation happens via the
 * shared verifier (server functions, loaders) and the Payload
 * strategy. Register globally in `src/start.ts` (and keep
 * `createCsrfMiddleware()` installed — defining `start.ts` disables
 * Start's automatic CSRF middleware).
 *
 * Thin adapter: the bounce decision is the shared framework-free
 * `decideAuthRedirect` from `@payload-auth-link/web` (unit-tested
 * there); this wrapper only maps its verdict onto a Start middleware.
 * The bounce is an explicit 303 so it always becomes a GET to
 * sign-in (never a replayed POST). The unit suite invokes the
 * registered server fn directly; e2e covers it inside the real
 * Start runtime.
 *
 * `/_serverFn/` is exempt by default (see `bounceServerFunctions`):
 * bouncing RPC corrupts the server-function protocol (redirect
 * followed with a JSON Accept → Start 406). Server functions
 * authenticate themselves via the shared verifier.
 */
export function createAuthRequestMiddleware(options: AuthRequestMiddlewareOptions) {
  const publicPaths =
    options.bounceServerFunctions === true
      ? options.publicPaths
      : [...(options.publicPaths ?? []), serverFunctionsPath]
  const resolved: AuthRedirectOptions = { ...options, publicPaths }
  return createMiddleware().server(({ request, next }) => {
    const target = decideAuthRedirect(request, resolved)
    if (target) {
      return Response.redirect(target, 303)
    }
    return next()
  })
}
