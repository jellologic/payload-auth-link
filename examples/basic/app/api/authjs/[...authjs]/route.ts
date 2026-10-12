import { createRouteHandlers } from '@payload-auth-link/next'
import { handleAuthJsRequest } from '../../../../lib/authjs'
import { clientKey, createRateLimiter, rateLimited } from '../../../../lib/rate-limit'

// Builder-owned throttle (in-memory, dev-scale — see lib/rate-limit.ts)
// over the authorize path: Auth.js core ships no rate limiting, so the
// route owns abuse control. Keyed by client IP with a generous ceiling
// (legit sign-in traffic is a handful of requests per run); production
// deployments key tighter behind a shared store.
const callbackThrottle = createRateLimiter({ windowMs: 600_000, max: 100 })

async function throttled(request: Request): Promise<Response> {
  const decision = callbackThrottle(clientKey(request))
  if (decision.limited) {
    return rateLimited(decision.retryAfterMs)
  }
  return handleAuthJsRequest(request)
}

export const { GET, POST } = createRouteHandlers(throttled)
