import { createSessionVerifier } from '@payload-auth-link/next'
import { exampleBaseURL } from './auth-cookie-names'

/**
 * Full server-side session validation, anchored to the configured origin
 * — never the request host headers (client-spoofable; the session cookie
 * is forwarded to this origin). `EXAMPLE_BASE_URL` matches the running
 * port in every mode (dev plus all e2e databases), so no per-mode
 * configuration is needed. Production deployments must set it to the
 * canonical origin.
 */
export const verifySession = createSessionVerifier({ baseUrl: exampleBaseURL })
