import { expect, test, type Page } from '@playwright/test'
import { gotoOwn, toggleToSignUp } from './helpers.js'

const password = 'e2e-test-password-1'
let counter = 0

function uniqueEmail(): string {
  counter += 1
  return `e2e-authjs-${Date.now()}-${counter}@example.com`
}

async function signUp(page: Page, email: string): Promise<void> {
  await gotoOwn(page, '/sign-in-authjs')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
}

test('auth.js sign-up provisions a Payload user, sign-out revokes, sign-in restores', async ({
  page,
}) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await expect(page.getByTestId('account-roles')).toContainText('user')

  // The plugin session endpoint serves the JIT-provisioned Payload user,
  // resolved through the Auth.js provider in the registry.
  const session = await page.request.get('/api/auth-link/session')
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { email: string; roles: string[] } }
  expect(body.user.email).toBe(email)
  expect(body.user.roles).toEqual(['user'])

  // Sign out through the user menu: the Auth.js JWT has nothing
  // server-side to revoke, so logout is cookie expiry — and the bounce
  // after proves the session cookie is really gone.
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)
  await gotoOwn(page, '/account')
  await expect(page).toHaveURL(/\/sign-in\?redirect=%2Faccount/)
  const revoked = await page.request.get('/api/auth-link/session')
  expect(revoked.status()).toBe(401)

  // Sign back in with the same credentials.
  await gotoOwn(page, '/sign-in-authjs')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
})

test('auth.js wrong passwords fail loudly on the sign-in form', async ({ page }) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)

  await gotoOwn(page, '/sign-in-authjs')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill('wrong-password-9')
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByRole('alert')).toBeVisible()
  await expect(page).toHaveURL(/\/sign-in-authjs/)
})

test('auth.js sign-up with a crafted redirect lands in-app', async ({ page }) => {
  const email = uniqueEmail()
  await gotoOwn(page, '/sign-in-authjs?redirect=//evil.example/phish')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  await expect(page).toHaveURL(/\/account/)
})

test('auth.js duplicate sign-ups are rejected with the form error', async ({ page }) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)

  await gotoOwn(page, '/sign-in-authjs')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.locator('p[role="alert"]')).toContainText(/already registered/i)
})
