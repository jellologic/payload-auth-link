import { getAuthJsSessionCookieNames } from '@payload-auth-link/provider-authjs/cookies'
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'

/**
 * Site origin. Single-sourced here (not in `lib/auth.ts`) so both the
 * engine and the Edge middleware share it without the middleware
 * importing server-only modules.
 */
export const exampleBaseURL = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100'

/**
 * Coexistence window (issue #51) for sites migrating off payload-auth:
 * its session cookies keep verifying (read-only) until `until`. The
 * same object goes to the engine (which honors it) and to `authLink`
 * (which asserts the two agree). EXAMPLE ONLY: a real window is weeks,
 * not decades — the far date keeps the e2e coexistence spec valid.
 */
export const legacySessionWindow = {
  until: '2099-01-01T00:00:00.000Z',
  cookieNames: ['payload-auth.session_token'],
} as const satisfies { until: string; cookieNames: readonly string[] }

/**
 * Session cookie names for the Edge middleware. Computed from the same
 * options shape the engine uses, through the dependency-free `cookies`
 * subpath — importing the engine itself would drag `payload` and
 * database code into the Edge bundle and fail the build.
 *
 * Builders with custom `advanced.cookies` names must mirror those
 * options here; a mismatch fails closed (everyone redirects to
 * sign-in), never open.
 */
export const sessionCookieNames: readonly string[] = [
  ...getBetterAuthSessionCookieNames({ baseURL: exampleBaseURL }),
  // Legacy names count as "signed in" for routing inside the window;
  // the session lookup decides whether they still verify.
  ...legacySessionWindow.cookieNames,
  ...getAuthJsSessionCookieNames({ baseURL: exampleBaseURL }),
]
