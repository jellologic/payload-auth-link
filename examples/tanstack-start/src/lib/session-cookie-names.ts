import { getAuthJsSessionCookieNames } from '@payload-auth-link/provider-authjs/cookies'
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'
import { exampleBaseURL } from './auth-base-url'

/**
 * Session cookie names for the request middleware. Computed from the
 * same options shape the engines use, through the dependency-free
 * `cookies` subpaths. A mismatch fails closed (everyone redirects to
 * sign-in), never open.
 */
export const sessionCookieNames: readonly string[] = [
  ...getBetterAuthSessionCookieNames({ baseURL: exampleBaseURL }),
  ...getAuthJsSessionCookieNames({ baseURL: exampleBaseURL }),
]
