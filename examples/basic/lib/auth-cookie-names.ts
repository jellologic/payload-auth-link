import { getAuthJsSessionCookieNames } from '@payload-auth-link/provider-authjs/cookies'
import { getBetterAuthSessionCookieNames } from '@payload-auth-link/provider-better-auth/cookies'

/**
 * Site origin. Single-sourced here (not in `lib/auth.ts`) so both the
 * engine and the Edge middleware share it without the middleware
 * importing server-only modules.
 */
export const exampleBaseURL = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100'

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
  ...getAuthJsSessionCookieNames({ baseURL: exampleBaseURL }),
]
