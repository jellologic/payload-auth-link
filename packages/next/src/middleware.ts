import { decideAuthRedirect, type AuthRedirectOptions } from '@payload-auth-link/web'
import { NextResponse, type NextRequest } from 'next/server.js'

/** Optimistic Edge middleware wiring; see {@link createAuthMiddleware}. */
export type AuthMiddlewareOptions = AuthRedirectOptions

/**
 * Edge-safe optimistic auth middleware: presence of any session cookie
 * lets the request through; absence redirects to sign-in. Optimistic is
 * deliberate — Edge cannot reach the database, so route protection here
 * is UX (bounce obvious anonymous traffic early), never authorization.
 * Real validation happens on Node via `createSessionVerifier` (server
 * components, route handlers) and the Payload strategy. Mount in
 * `middleware.ts` (or Next 16+ `proxy.ts`).
 *
 * Thin adapter: the bounce decision is the shared framework-free
 * `decideAuthRedirect` from `@payload-auth-link/web` (unit-tested
 * there); this wrapper only maps its verdict onto `NextResponse`.
 * The bounce is an explicit 303 so it always becomes a GET to
 * sign-in (never a replayed POST).
 */
export function createAuthMiddleware(
  options: AuthMiddlewareOptions
): (request: NextRequest) => NextResponse {
  return (request: NextRequest): NextResponse => {
    const target = decideAuthRedirect(request, options)
    if (target === null) {
      return NextResponse.next()
    }
    return NextResponse.redirect(target, 303)
  }
}
