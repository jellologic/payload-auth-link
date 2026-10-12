import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import { gotoOwn } from './helpers.js'

/**
 * Session lifecycle beyond the credentials happy path: stale and
 * replayed cookies bounce, cross-provider identities link onto one
 * Payload user, and OAuth entry points fail closed. The examples wire
 * no external OAuth identity provider (the suites run offline), so the
 * OAuth-link smoke drives the SAME verified-email link path an OAuth
 * sign-in takes — a second provider identity for an existing email —
 * through the two credentials providers, plus the unconfigured social
 * entry points of both SDKs.
 */

const password = 'e2e-test-password-1'
let counter = 0

function uniqueEmail(): string {
  counter += 1
  return `e2e-lifecycle-${Date.now()}-${counter}@example.com`
}

/** Raw Better Auth signup plus the local dev verification stamp. */
async function betterAuthSignUp(api: APIRequestContext, email: string): Promise<void> {
  const signup = await api.post('/api/auth/sign-up/email', {
    data: { name: email, email, password },
  })
  expect(signup.ok()).toBe(true)
  const stamped = await api.post('/api/dev-auto-verify', { data: { email } })
  expect(stamped.ok()).toBe(true)
}

async function sessionUserId(api: APIRequestContext): Promise<string | number> {
  const session = await api.get('/api/auth-link/session')
  expect(session.ok()).toBe(true)
  const { user } = (await session.json()) as { user: { id: string | number } }
  return user.id
}

/**
 * A dead cookie still passes the optimistic presence bounce, so the
 * proof is Node validation: the server-enforced page bounces to
 * sign-in, the hydrated account page renders signed out, and the
 * session endpoint 401s.
 */
async function expectBounced(page: Page): Promise<void> {
  await gotoOwn(page, '/admin-only')
  // Middleware bounces encode the path; server-side redirects may not.
  await expect(page).toHaveURL(/\/sign-in\?redirect=(%2F|\/)admin-only/)
  await gotoOwn(page, '/account')
  await expect(page.getByText('Signed out.')).toBeVisible()
  await expect(page.getByTestId('account-email')).toHaveCount(0)
  const session = await page.request.get('/api/auth-link/session')
  expect(session.status()).toBe(401)
}

test('a corrupted session cookie bounces to sign-in and 401s', async ({ page }) => {
  await betterAuthSignUp(page.request, uniqueEmail())
  const live = await page.context().cookies()
  expect(live.length).toBeGreaterThan(0)
  // Cookie presence passes the optimistic bounce; Node validation must
  // still reject the garbage value.
  await page.context().clearCookies()
  await page
    .context()
    .addCookies(live.map((cookie) => ({ ...cookie, value: 'stale-garbage-value' })))
  await expectBounced(page)
})

test('a revoked session cookie replayed after logout bounces', async ({ page }) => {
  await betterAuthSignUp(page.request, uniqueEmail())
  const live = await page.context().cookies()
  const logout = await page.request.delete('/api/auth-link/session', {
    headers: { 'x-auth-link-csrf': '1' },
  })
  expect(logout.ok()).toBe(true)
  // Replay the pre-logout cookies: the database session is gone, so the
  // exact same token must no longer authenticate.
  await page.context().addCookies(live)
  await expectBounced(page)
})

test('a second provider identity links onto the same Payload user', async ({ page }) => {
  const email = uniqueEmail()
  await betterAuthSignUp(page.request, email)
  const firstId = await sessionUserId(page.request)
  const logout = await page.request.delete('/api/auth-link/session', {
    headers: { 'x-auth-link-csrf': '1' },
  })
  expect(logout.ok()).toBe(true)

  // Same verified email through the other provider: links, never forks.
  const signup = await page.request.post('/api/authjs-signup', { data: { email, password } })
  expect(signup.ok()).toBe(true)
  await gotoOwn(page, '/sign-in-authjs')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  expect(await sessionUserId(page.request)).toEqual(firstId)
})

test('unconfigured OAuth entry points fail closed', async ({ page }) => {
  const social = await page.request.post('/api/auth/sign-in/social', {
    data: { provider: 'github', callbackURL: '/account' },
    maxRedirects: 0,
  })
  expect(social.ok()).toBe(false)
  const authjs = await page.request.get('/api/authjs/signin/github', { maxRedirects: 0 })
  // Auth.js answers unknown providers with a redirect to its error or
  // sign-in page, never an authorization URL off-site.
  const location = authjs.headers()['location'] ?? ''
  expect(location.startsWith('/') || location.startsWith('http://localhost')).toBe(true)
  const session = await page.request.get('/api/auth-link/session')
  expect(session.status()).toBe(401)
})
