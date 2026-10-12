import {
  createSessionVerifier,
  getSessionUserFromRequest,
  requireRoles,
} from '@payload-auth-link/tanstack-start'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { notFound, redirect } from '@tanstack/react-router'
import { exampleBaseURL } from './auth-base-url'

/**
 * Full server-side session validation, anchored to the configured
 * origin — never the request host headers (client-spoofable; the
 * session cookie is forwarded to this origin). `EXAMPLE_BASE_URL`
 * matches the running port in every mode. Production deployments
 * must set it to the canonical origin.
 */
export const verifySession = createSessionVerifier({ baseUrl: exampleBaseURL })

/** Session user for loaders and components, via the shared verifier. */
export const getSessionUser = createServerFn({ method: 'GET' }).handler(() =>
  getSessionUserFromRequest(getRequest(), verifySession)
)

/**
 * Admin gate for `beforeLoad`: runs server-side on SSR and as RPC on
 * client navigation, so `getRequest()` is always in scope. Anonymous
 * visitors bounce to sign-in, non-admins hit notFound().
 */
export const requireAdminUser = createServerFn({ method: 'GET' }).handler(() =>
  requireRoles(getRequest().headers, verifySession, {
    roles: ['admin'],
    // `redirect()` / `notFound()` produce the router's control-flow
    // signal — they must be thrown, not merely returned, or execution
    // falls through to requireRoles' default errors.
    onAnonymous: () => {
      // TanStack control-flow signals are thrown, not Errors, by design.
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      throw redirect({ to: '/sign-in', search: { redirect: '/admin-only' } })
    },
    onDenied: () => {
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      throw notFound()
    },
  })
)
