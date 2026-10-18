import { expect, test, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { gotoOwn, gotoSettled, RETRY_ON_RESET, toggleToSignUp } from './helpers.js'

const password = 'e2e-test-password-1'
let counter = 0

function uniqueEmail(): string {
  counter += 1
  return `e2e-${Date.now()}-${counter}@example.com`
}

async function signUp(page: Page, email: string): Promise<void> {
  await gotoOwn(page, '/sign-in')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
}

test('anonymous users bounce to sign-in with the intercepted path', async ({ page }) => {
  await gotoOwn(page, '/account')
  await expect(page).toHaveURL(/\/sign-in\?redirect=%2Faccount/)
  await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible()
})

test('sign-up provisions a Payload user, sign-out revokes, sign-in restores', async ({ page }) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await expect(page.getByTestId('account-roles')).toContainText('user')

  // The plugin session endpoint serves the JIT-provisioned Payload user.
  const session = await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { email: string; roles: string[] } }
  expect(body.user.email).toBe(email)
  expect(body.user.roles).toEqual(['user'])

  // Sign out through the user menu: revoked everywhere, bounced after.
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)
  await gotoOwn(page, '/account')
  await expect(page).toHaveURL(/\/sign-in\?redirect=%2Faccount/)
  const revoked = await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(revoked.status()).toBe(401)

  // Sign back in with the same credentials.
  await gotoOwn(page, '/sign-in')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
})

test('wrong passwords fail loudly on the sign-in form', async ({ page }) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)

  await gotoOwn(page, '/sign-in')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill('wrong-password-9')
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByRole('alert')).toBeVisible()
  await expect(page).toHaveURL(/\/sign-in/)
})

test('a crafted redirect cannot bounce fresh logins off-site', async ({ page }) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)

  await gotoOwn(page, '/sign-in?redirect=https://evil.example/phish')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  await expect(page).toHaveURL(/\/account/)
})

test('a query-bearing redirect lands with its query intact', async ({ page }) => {
  const email = uniqueEmail()
  await signUp(page, email)
  await page.getByRole('button', { name: /^sign out$/i }).click()
  await expect(page).toHaveURL(/\/$/)

  await gotoOwn(page, '/sign-in?redirect=%2Faccount%3Ftab%3D1%26mode%3Dedit')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  await expect(page).toHaveURL(/\/account\?tab=1&mode=edit/)
})

test('anonymous visitors bounce from /admin-only to sign-in', async ({ page }) => {
  await gotoSettled(page, '/admin-only')
  await expect(page).toHaveURL(/\/sign-in\?redirect=%2Fadmin-only/)
})

test('non-admin users get a 404 on /admin-only, admins see the content', async ({
  page,
  browser,
  baseURL,
}) => {
  const email = uniqueEmail()
  await signUp(page, email)

  // Member: 404, and the secret is nowhere in the response — the server
  // enforces before rendering (a client gate would ship it).
  const denied = await page.request.get('/admin-only')
  expect(denied.status()).toBe(404)
  expect(await denied.text()).not.toContain('Secret admin content')
  await gotoSettled(page, '/admin-only')
  await expect(page.getByTestId('admin-denied')).toBeVisible()

  // Escalate to admin through the Payload API as the seeded local admin.
  const session = await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  const { user } = (await session.json()) as { user: { id: string | number } }
  // The shared run-level admin session (see admin-session.ts) lives in
  // its own context; concurrent admin logins would race.
  const admin = await adminContext(browser, baseURL)
  const adminPage = await admin.newPage()
  await gotoSettled(adminPage, '/admin')
  // Escalate through in-browser fetch: it carries the admin login
  // cookie exactly like the Payload admin UI does.
  const patched = await adminPage.evaluate(async (id: string) => {
    const response = await fetch(`/api/users/${id}`, {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ roles: ['admin'] }),
    })
    return { status: response.status, body: await response.text() }
  }, String(user.id))
  expect(patched.status).toBe(200)
  await admin.close()

  // Back as the escalated user: granted, with the server-rendered content.
  await page.context().clearCookies()
  await gotoOwn(page, '/sign-in')
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  await gotoSettled(page, '/admin-only')
  await expect(page.getByTestId('admin-granted')).toContainText(email)
})
