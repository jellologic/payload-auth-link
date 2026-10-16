/**
 * Site origin. Single-sourced here so the engines and (later) the
 * request middleware share it without importing server-only modules.
 */
export const exampleBaseURL = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3200'

/**
 * Coexistence window (issue #51) for sites migrating off payload-auth:
 * its session cookies keep verifying (read-only) until `until`. The
 * same object goes to the engine (which honors it), to `authLink`
 * (which asserts the two agree), and to the request middleware's
 * cookie names. EXAMPLE ONLY: a real window is weeks, not decades —
 * the far date keeps the e2e coexistence spec valid.
 */
export const legacySessionWindow = {
  until: '2099-01-01T00:00:00.000Z',
  cookieNames: ['payload-auth.session_token'],
} as const satisfies { until: string; cookieNames: readonly string[] }
