import { expect, test } from '@playwright/test'

// SEC-13: the builder-owned signup throttle 429s abusive repeats. The
// throttle is keyed per email with a fresh address per worker, so this
// spec can never consume another spec's budget (parallel files share
// one server) and vice versa.
test('builder signup throttles abusive repeats with 429', async ({ page }) => {
  const email = `e2e-rl-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}@example.com`
  const statuses: number[] = []
  let retryAfter: string | null = null
  for (let attempt = 0; attempt < 11; attempt++) {
    const response = await page.request.post('/api/authjs-signup', {
      data: { email, password: 'e2e-test-password-1' },
    })
    statuses.push(response.status())
    if (response.status() === 429) {
      retryAfter = response.headers()['retry-after'] ?? null
    }
  }
  // First creates, the next nine are duplicate rejections, the eleventh
  // trips the throttle (max 10 per 10 minutes per email).
  expect(statuses[0]).toBe(200)
  expect(statuses.slice(1, 10)).toEqual(Array(9).fill(409))
  expect(statuses[10]).toBe(429)
  expect(retryAfter).not.toBeNull()
})
