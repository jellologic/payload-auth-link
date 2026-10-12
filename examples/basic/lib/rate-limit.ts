/**
 * Minimal in-memory sliding-window throttle for the example auth routes.
 * Builder-owned reference pattern (see "Rate limiting" in
 * `docs/guide-authjs.md`): the library ships no throttles, so each
 * deployment owns abuse control.
 *
 * In-memory state is a dev-scale stand-in, not a production design: it
 * neither spans instances nor survives restarts, and the key map grows
 * with distinct keys (entries are pruned per key on access, but keys
 * themselves are never evicted). Production deployments need a shared
 * store with TTLs (Redis, Upstash, Postgres counters).
 */
export type RateLimitDecision = { limited: false } | { limited: true; retryAfterMs: number }

export function createRateLimiter(options: {
  /** Window length in milliseconds. */
  windowMs: number
  /** Max attempts per key per window; the next one 429s. */
  max: number
  /** Clock override for tests; defaults to `Date.now`. */
  now?: () => number
}): (key: string) => RateLimitDecision {
  const hits = new Map<string, number[]>()
  const now = options.now ?? Date.now
  return (key: string): RateLimitDecision => {
    const at = now()
    const cutoff = at - options.windowMs
    const recent = (hits.get(key) ?? []).filter((stamp) => stamp > cutoff)
    if (recent.length >= options.max) {
      const oldest = recent[0] ?? at
      return { limited: true, retryAfterMs: oldest + options.windowMs - at }
    }
    recent.push(at)
    hits.set(key, recent)
    return { limited: false }
  }
}

/** 429 response with `Retry-After`, for throttled auth routes. */
export function rateLimited(retryAfterMs: number): Response {
  const seconds = Math.max(1, Math.ceil(retryAfterMs / 1000))
  return Response.json(
    { error: 'too many attempts, slow down' },
    { status: 429, headers: { 'Retry-After': String(seconds) } }
  )
}

/**
 * Best-effort client key: the first forwarded IP, else a shared bucket.
 * Behind one proxy this separates clients; direct localhost traffic
 * shares the bucket, which is why per-route thresholds stay generous
 * here and per-email keys guard the signup route instead.
 */
export function clientKey(request: Request): string {
  const first = request.headers.get('x-forwarded-for')?.split(',', 1)[0]?.trim()
  return first === undefined || first === '' ? 'unknown' : first
}
