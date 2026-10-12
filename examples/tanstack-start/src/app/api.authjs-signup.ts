import { InvalidEmailError, UserExistsError } from '@payload-auth-link/core'
import { WeakPasswordError } from '@payload-auth-link/provider-authjs'
import { createFileRoute } from '@tanstack/react-router'
import { registerAuthJsUser } from '../lib/authjs.js'
import { createRateLimiter, rateLimited } from '../lib/rate-limit.js'

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
        if (result.isErr()) {
          const error = result.error
          if (error instanceof UserExistsError) {
            return Response.json({ error: 'that email is already registered' }, { status: 409 })
          }
          if (error instanceof WeakPasswordError || error instanceof InvalidEmailError) {
            return Response.json({ error: error.message }, { status: 400 })
          }
          // AdapterOperationError: storage failure. Generic message — the
          // cause may carry database internals that must not leak to clients.
          return Response.json({ error: 'registration failed, try again later' }, { status: 500 })
        }
        return Response.json({ email: result.value.email })
      },
    },
  },
})
