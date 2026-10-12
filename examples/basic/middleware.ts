import { createAuthMiddleware } from '@payload-auth-link/next'
import { sessionCookieNames } from './lib/auth-cookie-names'

export default createAuthMiddleware({
  sessionCookieNames,
  publicPaths: ['/', '/sign-in', '/sign-in-authjs'],
})

export const config = {
  // Segment-anchored exclusions: bare `api`/`admin` prefixes would also
  // exempt frontend routes like `/admin-only` from the middleware.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api(?:/|$)|admin(?:/|$)).*)'],
}
