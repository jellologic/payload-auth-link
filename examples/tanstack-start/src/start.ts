import { createAuthRequestMiddleware } from '@payload-auth-link/tanstack-start'
import { createCsrfMiddleware, createStart } from '@tanstack/react-start'
import { sessionCookieNames } from './lib/session-cookie-names'

const authRequestMiddleware = createAuthRequestMiddleware({
  sessionCookieNames,
  publicPaths: [
    '/',
    '/sign-in',
    '/sign-in-authjs',
    '/favicon.ico',
    // Payload REST + admin carry their own auth; client assets must
    // never bounce (anonymous browsers fetch them cookieless).
    /^\/api(\/|$)/,
    /^\/admin(\/|$)/,
    // No /_serverFn/ entry: the middleware exempts Start RPC by
    // default (a redirect there corrupts the server-function
    // protocol). Server functions authenticate themselves
    // (verifier returns null / throws redirect|notFound).
    /^\/@/,
    /^\/_build(\/|$)/,
    /^\/src\//,
    /^\/node_modules\//,
  ],
})

// Defining start.ts disables Start's automatic CSRF middleware —
// reinstall it explicitly for server functions.
const csrfMiddleware = createCsrfMiddleware({
  filter: (ctx) => ctx.handlerType === 'serverFn',
})

export const startInstance = createStart(() => ({
  requestMiddleware: [csrfMiddleware, authRequestMiddleware],
}))
