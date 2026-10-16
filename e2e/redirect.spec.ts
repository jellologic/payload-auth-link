import { expect, test, type Page } from '@playwright/test'
import { gotoOwn, toggleToSignUp } from './helpers.js'

/**
 * Post-login redirect matrix with dot segments. `safeRedirectPath`
 * normalises the destination the way the browser will resolve it, so a
 * destination that only LOOKS like a page (`/x/../api/...`,
 * `/./sign-in`, `/%2e%2e/api/x`) falls back to `/account` instead of
 * landing a fresh login on JSON or looping on the sign-in page — and a
 * benign dot-segment path lands on its normalised form.
 */

const password = 'e2e-test-password-1'

function uniqueEmail(): string {
  return `e2e-redirect-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`
}

async function signOutQuietly(page: Page): Promise<void> {
  const response = await page.request.delete('/api/auth-link/session', {
    headers: { 'x-auth-link-csrf': '1' },
  })
  expect([200, 401]).toContain(response.status())
}

async function signInWithRedirect(page: Page, email: string, redirect: string): Promise<void> {
  await gotoOwn(page, `/sign-in?redirect=${encodeURIComponent(redirect)}`)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
}

const matrix: ReadonlyArray<{ readonly redirect: string; readonly lands: RegExp }> = [
  // Under the API prefix once resolved: fall back.
  { redirect: '/x/../api/auth-link/session', lands: /\/account$/ },
  { redirect: '/%2e%2e/api/x', lands: /\/account$/ },
  { redirect: '/./api/x', lands: /\/account$/ },
  // The sign-in page once resolved (a login loop): fall back.
  { redirect: '/./sign-in', lands: /\/account$/ },
  { redirect: '/x/%2e%2e/sign-in', lands: /\/account$/ },
  // Protocol-relative once resolved: fall back, never off-site.
  { redirect: '/.//evil.example/phish', lands: /\/account$/ },
  // Benign: lands on the normalised path, query intact.
  { redirect: '/x/../account?tab=1', lands: /\/account\?tab=1$/ },
]

test('post-login redirects normalise dot segments before the safety rules', async ({ page }) => {
  test.setTimeout(180_000)
  const email = uniqueEmail()
  await gotoOwn(page, '/sign-in')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })

  for (const { redirect, lands } of matrix) {
    await signOutQuietly(page)
    await signInWithRedirect(page, email, redirect)
    await expect(page.getByTestId('account-email'), redirect).toContainText(email, {
      timeout: 30_000,
    })
    await expect(page, redirect).toHaveURL(lands)
    const landed = new URL(page.url())
    const baseURL = test.info().project.use.baseURL
    if (baseURL !== undefined) {
      expect(landed.origin, redirect).toBe(new URL(baseURL).origin)
    }
    expect(landed.pathname.startsWith('/api'), redirect).toBe(false)
  }
})
