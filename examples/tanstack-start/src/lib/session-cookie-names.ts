import { getAuthJsSessionCookieNames } from '@payload-auth-link/provider-authjs/cookies'
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'
import { exampleBaseURL, legacySessionWindow } from './auth-base-url'

/**
 * Session cookie names for the request middleware. Computed from the
 * same options shape the engines use, through the dependency-free
 * `cookies` subpaths. A mismatch fails closed (everyone redirects to
 * sign-in), never open.
 */
export const sessionCookieNames: readonly string[] = [
  ...getBetterAuthSessionCookieNames({ baseURL: exampleBaseURL }),
  // Legacy names count as "signed in" for routing inside the window;
  // the session lookup decides whether they still verify.
  ...legacySessionWindow.cookieNames,
  ...getAuthJsSessionCookieNames({ baseURL: exampleBaseURL }),
]
