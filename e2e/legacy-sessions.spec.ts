import { expect, test } from '@playwright/test'
import { gotoOwn, signUpVerified } from './helpers.js'

/**
 * Legacy payload-auth session coexistence (issue #51), wired in both
 * examples: the engine honors `payload-auth.session_token` READ-ONLY
 * inside the window (re-presented under the current name), and the
 * plugin option asserts the same window. A site switching off
 * payload-auth keeps its signed-in users: a browser carrying only the
 * legacy cookie still resolves to the same Payload user, on the API
 * and on server-rendered pages. A forged legacy value never does.
 */

const legacyCookieName = 'payload-auth.session_token'

test('a legacy payload-auth session cookie keeps the user signed in inside the window', async ({
  browser,
  baseURL,
}) => {
  const origin = baseURL ?? ''
  const email = `e2e-legacy-${test.info().project.name}-${Date.now()}@example.com`
  const signup = await browser.newContext({ baseURL: origin })
  const legacy = await browser.newContext({ baseURL: origin })
  const forged = await browser.newContext({ baseURL: origin })
  try {
    const { userId } = await signUpVerified(signup.request, email)
    const current = (await signup.cookies()).find(
      (cookie) => cookie.name === 'better-auth.session_token'
    )
    if (current === undefined) {
      throw new Error('sign-up set no better-auth.session_token cookie')
    }

    // Same signed token, legacy name only (what a payload-auth site's
    // visitors still carry after the switch).
    await legacy.addCookies([{ name: legacyCookieName, value: current.value, url: origin }])
    const resolved = await legacy.request.get('/api/auth-link/session')
    expect(resolved.status()).toBe(200)
    const body = (await resolved.json()) as { user: { id: string; email: string } }
    expect(body.user.email).toBe(email)
    expect(String(body.user.id)).toBe(userId)

    // Server-rendered pages see the same user (the middleware counts
    // the legacy name as a session cookie inside the window).
    const page = await legacy.newPage()
    await gotoOwn(page, '/account')
    await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })

    // A forged legacy value is not a session.
    await forged.addCookies([{ name: legacyCookieName, value: 'forged.value', url: origin }])
    const refused = await forged.request.get('/api/auth-link/session')
    expect(refused.status()).toBe(401)
  } finally {
    await Promise.all([signup.close(), legacy.close(), forged.close()])
  }
})
