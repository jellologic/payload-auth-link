import { createFileRoute } from '@tanstack/react-router'
import { registerAuthJsUser } from '../lib/authjs.js'
import { createRateLimiter, rateLimited } from '../lib/rate-limit.js'
import { signupResponse } from '../lib/signup-response.js'

// Builder-owned throttle (in-memory, dev-scale — see lib/rate-limit.ts).
// Per-email: legit signups use each address once, so abuse of one address
// can never lock out another.
const signupThrottle = createRateLimiter({ windowMs: 600_000, max: 10 })

/**
 * Builder-owned credentials signup. Auth.js credentials store nothing
 * themselves — registration is an explicit service call, and the
 * verification stamp is builder signup policy: the plugin refuses to
 * link unverified identities, so credentials users stay locked out
 * until the builder verifies them.
 *
 * LOCAL EXAMPLE ONLY: this route stamps every signup verified
 * immediately (there is no email delivery here), mirroring the
 * Better Auth side's `requireEmailVerification: false`. Production
 * builders verify out-of-band (email link, admin approval) and stamp
 * `emailVerified` only then.
 */
export const Route = createFileRoute('/api/authjs-signup')({
  server: {
    handlers: {
      POST: async ({ request }: { request: Request }) => {
        const body = (await request.json().catch(() => null)) as {
          email?: unknown
          password?: unknown
        } | null
        if (typeof body?.email !== 'string' || typeof body?.password !== 'string') {
          return Response.json({ error: 'email and password are required' }, { status: 400 })
        }
        const decision = signupThrottle(body.email.toLowerCase())
        if (decision.limited) {
          return rateLimited(decision.retryAfterMs)
        }
        const result = await registerAuthJsUser({
          email: body.email,
          password: body.password,
          name: body.email,
          emailVerified: new Date(),
        })
        // Uniform response for new and existing emails (no enumeration
        // oracle); duplicates are reported out-of-band. This local example
        // has no email delivery, so the notice is a deliberate no-op —
        // production builders email the address owner here.
        return signupResponse(result.isErr() ? result.error : null, body.email, () => {})
      },
    },
  },
})
