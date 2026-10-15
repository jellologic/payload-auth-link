import { createAuthMiddleware, isAPIError } from 'better-auth/api'
import type { BetterAuthPlugin } from 'better-auth'
import type { AuthMethod } from '@payload-auth-link/core'

/** The method value recorded on server-side mints (no 2FA challenge ran). */
export const MINT_METHOD: AuthMethod = 'server-mint'
/** The method recorded when the server vouches a second factor it verified itself. */
export const STEP_UP_METHOD: AuthMethod = 'server-step-up'
/** Session methods whose recorded value counts as an MFA proof. */
export const MFA_METHODS: readonly AuthMethod[] = [STEP_UP_METHOD, 'two-factor']

/**
 * The endpoints whose SUCCESS creates (or finally proves) a session,
 * mapped to the authentication method recorded on the session row.
 * Exact paths or prefixes — Better Auth's own route names, so the
 * mapping tracks the flow the app actually runs. Paths outside this
 * table record nothing (null), which fails closed at the MFA gate.
 */
const METHOD_BY_PATH: readonly {
  readonly matches: (path: string) => boolean
  readonly method: AuthMethod
}[] = [
  { matches: (path) => path.startsWith('/two-factor/verify'), method: 'two-factor' },
  { matches: (path) => path === '/sign-in/email', method: 'password' },
  { matches: (path) => path === '/magic-link/verify', method: 'magic-link' },
  { matches: (path) => path === '/email-otp/sign-in-email-otp', method: 'email-otp' },
  {
    matches: (path) => path.startsWith('/callback/') || path.startsWith('/oauth2/callback/'),
    method: 'oauth',
  },
  { matches: (path) => path === '/passkey/authenticate', method: 'passkey' },
]

function methodForPath(path: string | undefined): AuthMethod | null {
  if (path === undefined) {
    return null
  }
  for (const entry of METHOD_BY_PATH) {
    if (entry.matches(path)) {
      return entry.method
    }
  }
  return null
}

/** `token.<base64 signature>` → `token`: strip BA's cookie signature. */
function stripSignature(value: string): string {
  const dot = value.lastIndexOf('.')
  return dot > 0 ? value.slice(0, dot) : value
}

/** The raw session token inside one Set-Cookie entry, if it is the session cookie. */
function rawTokenFromSetCookie(entry: string, name: string): string | null {
  if (!entry.startsWith(`${name}=`)) {
    return null
  }
  const pair = entry.slice(name.length + 1).split(';', 1)[0]
  return pair === undefined || pair === '' ? null : stripSignature(pair)
}

/** The raw session token from a request Cookie header (signed form). */
function rawTokenFromRequestCookie(cookieHeader: string, name: string): string | null {
  const match = new RegExp(
    `(?:^|;\\s*)${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=([^;]+)`
  ).exec(cookieHeader)
  const value = match?.[1]
  return value === undefined || value === '' ? null : stripSignature(value)
}

/**
 * The engine's internal session-provenance plugin. Two jobs:
 *
 * 1. **Schema** — one nullable, input-excluded field on Better Auth's
 *    session model: `authenticationMethod`, recording HOW the session
 *    came into being.
 * 2. **Recording** — `hooks.after` on the endpoints whose success
 *    creates (or finally proves) a session: password sign-in records
 *    `password`, the two-factor verifications upgrade their session to
 *    `two-factor`, OAuth callbacks record `oauth`, and so on. A
 *    single-factor session is never relabelled — the second factor's
 *    own endpoint is the only path that writes `two-factor`, and
 *    server-side mints write `server-mint`/`server-step-up` (port.ts).
 *
 * The server session API reads this per-session fact for its
 * assurance projection; enrollment flags are never consulted. Paths
 * outside the table and rows that predate the field record nothing —
 * `null` reads as "no recorded method", which the assurance projection
 * treats as proving nothing (fail closed).
 */
export const sessionProvenancePlugin: BetterAuthPlugin = {
  id: 'payload-auth-link-session-provenance',
  init: () => ({ context: {} }),
  schema: {
    session: {
      fields: {
        authenticationMethod: { type: 'string', required: false, input: false },
      },
    },
  },
  hooks:
    process.env.PROVENANCE_HOOKS_OFF === '1'
      ? undefined
      : {
          after: [
            {
              matcher: (ctx) => methodForPath(ctx.path) !== null,
              handler: createAuthMiddleware(async (ctx) => {
                const method = methodForPath(ctx.path)
                if (method === null) {
                  return
                }
                // Record ONLY successful requests. BA's after-hooks run
                // even when the endpoint returned an error response
                // (verify-totp RETURNS a 401 for a wrong code instead
                // of unwinding the chain), so success must be checked
                // explicitly. This mirrors BA's own
                // `getEndpointResponse` (utils/plugin-helper): the
                // endpoint's result must be a 200 body — non-2xx
                // responses and thrown APIErrors record nothing (a
                // wrong 2FA code must never relabel the presented
                // session).
                const returned = (ctx.context as { returned?: unknown }).returned
                if (returned === null || returned === undefined) {
                  return
                }
                if (returned instanceof Response && returned.status !== 200) {
                  return
                }
                if (isAPIError(returned)) {
                  return
                }
                const context = ctx.context as {
                  authCookies?: { sessionToken?: { name?: string } }
                  responseHeaders?: Headers | undefined
                  request?: { headers?: Headers }
                  internalAdapter?: {
                    updateSession?:
                      | ((token: string, data: Record<string, unknown>) => Promise<unknown>)
                      | undefined
                  }
                }
                const name = context.authCookies?.sessionToken?.name
                const updateSession = context.internalAdapter?.updateSession
                if (
                  typeof name !== 'string' ||
                  name === '' ||
                  typeof updateSession !== 'function'
                ) {
                  // Cannot resolve the token surface: record nothing rather
                  // than guess (fail closed).
                  return
                }
                // Prefer the response's own cookie (fresh sign-ins and
                // rotations), then the request's cookie (verify endpoints run
                // against the presented session).
                let token: string | null = null
                const setCookies = context.responseHeaders?.getSetCookie?.() ?? []
                for (const entry of setCookies) {
                  const found = rawTokenFromSetCookie(entry, name)
                  if (found !== null) {
                    token = found
                    break
                  }
                }
                if (token === null) {
                  token = rawTokenFromRequestCookie(
                    context.request?.headers?.get('cookie') ?? '',
                    name
                  )
                }
                if (token === null) {
                  return
                }
                await updateSession(token, { authenticationMethod: method })
              }),
            },
          ],
        },
}
