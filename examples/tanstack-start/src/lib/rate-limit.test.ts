import { describe, expect, it } from 'vitest'
import { clientKey, createRateLimiter, rateLimited } from './rate-limit.js'

describe('createRateLimiter', () => {
  it('allows max attempts per window, then 429s with a retry hint', () => {
    const check = createRateLimiter({ windowMs: 60_000, max: 3, now: () => 1_000_000 })
    expect(check('a@b.c')).toEqual({ limited: false })
    expect(check('a@b.c')).toEqual({ limited: false })
    expect(check('a@b.c')).toEqual({ limited: false })
    const throttled = check('a@b.c')
    expect(throttled.limited).toBe(true)
    if (throttled.limited) {
      expect(throttled.retryAfterMs).toBe(60_000)
    }
    // Other keys are unaffected.
    expect(check('other@b.c')).toEqual({ limited: false })
  })

  it('slides the window as attempts age out', () => {
    let now = 0
    const check = createRateLimiter({ windowMs: 100, max: 2, now: () => now })
    expect(check('k').limited).toBe(false)
    expect(check('k').limited).toBe(false)
    expect(check('k').limited).toBe(true)
    now = 101
    expect(check('k').limited).toBe(false)
    expect(check('k').limited).toBe(false)
    expect(check('k').limited).toBe(true)
  })
})

describe('rateLimited', () => {
  it('returns 429 with a Retry-After of at least one second', async () => {
    const response = rateLimited(500)
    expect(response.status).toBe(429)
    expect(response.headers.get('Retry-After')).toBe('1')
    const body: unknown = await response.json()
    expect(body).toEqual({ error: 'too many attempts, slow down' })
    expect(rateLimited(61_000).headers.get('Retry-After')).toBe('61')
  })
})

describe('clientKey', () => {
  it('takes the first forwarded IP, else the shared bucket', () => {
    const forwarded = new Request('http://x.test/', {
      headers: { 'x-forwarded-for': '203.0.113.7, 70.41.3.18' },
    })
    expect(clientKey(forwarded)).toBe('203.0.113.7')
    expect(clientKey(new Request('http://x.test/'))).toBe('unknown')
  })
})
