import { createServerRouteHandlers } from '@payload-auth-link/tanstack-start'
import { createFileRoute } from '@tanstack/react-router'
import { handleAuthJsRequest } from '../lib/authjs.js'
import { clientKey, createRateLimiter, rateLimited } from '../lib/rate-limit.js'

// Builder-owned throttle (in-memory, dev-scale — see lib/rate-limit.ts)
// over the authorize path: Auth.js core ships no rate limiting, so the
// route owns abuse control. Keyed by client IP with a generous ceiling
// (legit sign-in traffic is a handful of requests per run); production
// deployments key tighter behind a shared store.
const callbackThrottle = createRateLimiter({ windowMs: 600_000, max: 100 })

// Per-identifier attempt cap for the email OTP/link callback
// (CAP-2/CAP-18) — see the Next example's route for the rationale.
const otpAttemptThrottle = createRateLimiter({ windowMs: 600_000, max: 3 })

async function throttled(request: Request): Promise<Response> {
  const url = new URL(request.url)
  if (url.pathname.endsWith('/callback/resend')) {
    const email = url.searchParams.get('email') ?? ''
    const decision = otpAttemptThrottle(`otp:${clientKey(request)}:${email.toLowerCase()}`)
    if (decision.limited) {
      return rateLimited(decision.retryAfterMs)
    }
  }
  const decision = callbackThrottle(clientKey(request))
  if (decision.limited) {
    return rateLimited(decision.retryAfterMs)
  }
  return handleAuthJsRequest(request)
}

export const Route = createFileRoute('/api/authjs/$')({
  server: {
    handlers: createServerRouteHandlers(throttled),
  },
})
