import { expect, test, type APIRequestContext } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { gotoSettled, RETRY_ON_RESET } from './helpers.js'

/**
 * An admin signs into the Payload admin through the PROVIDER form of
 * the plugin's login view (#55/#72) and lands on the dashboard.
 *
 * The seeded admin cannot be the subject: it is unlinked (it signs in
 * through the break-glass local form), and its one login per run is
 * shared by every spec — a second concurrent login of the same user
 * races on Payload's per-user `sessions` array (see
 * `admin-session.ts`). So a fresh provider user is registered, the
 * shared admin session promotes it to `admin`, and that user signs in
 * through the provider form in its own fresh context.
 */
const password = 'e2e-test-password-1'

async function signUpVerified(request: APIRequestContext, email: string): Promise<string> {
  const signup = await request.post('/api/auth/sign-up/email', {
    data: { name: email, email, password },
  })
  expect(signup.ok()).toBe(true)
  const stamped = await request.post('/api/dev-auto-verify', { data: { email } })
  expect(stamped.ok()).toBe(true)
  const session = await request.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { id: string | number } }
  return String(body.user.id)
}

test('a provider-linked admin signs in through the provider login view', async ({
  page,
  browser,
  baseURL,
}) => {
  const email = `e2e-admin-provider-${Date.now()}@example.com`
  const userId = await signUpVerified(page.request, email)

  // Promote through the shared admin session, by in-browser fetch: it
  // carries the admin cookie and a same-origin Origin like the admin UI.
  const admin = await adminContext(browser, baseURL)
  try {
    const adminPage = await admin.newPage()
    await gotoSettled(adminPage, '/admin')
    const patched = await adminPage.evaluate(async (id: string) => {
      const response = await fetch(`/api/users/${id}`, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ roles: ['admin'] }),
      })
      return { status: response.status, body: await response.text() }
    }, userId)
    expect(patched.status, `promote PATCH: ${patched.body}`).toBe(200)
  } finally {
    await admin.close()
  }

  // Signed out (the sign-up session would bounce /admin/login straight
  // to the dashboard), then in through the provider form.
  await page.context().clearCookies()
  await gotoSettled(page, '/admin/login')
  const providerForm = page.locator('form', { hasText: 'Provider sign-in' })
  await expect(providerForm).toBeVisible()
  // Hydration guard: a click before React hydrates submits natively and
  // is lost, so retry the fill + submit until the redirect is observed.
  await expect(async () => {
    // A slow earlier attempt may have redirected after its wait expired.
    if (/\/admin\/?$/.test(new URL(page.url()).pathname)) {
      return
    }
    await providerForm.getByLabel(/email/i).fill(email)
    await providerForm.getByLabel(/password/i).fill(password)
    await providerForm.getByRole('button', { name: 'Sign in with provider', exact: true }).click()
    await page.waitForURL(/\/admin\/?$/, { timeout: 10_000 })
  }).toPass({ timeout: 60_000 })

  // The dashboard renders for the provider session (not bounced back to
  // login), and the session endpoint reports the admin role.
  await expect(page).not.toHaveURL(/\/admin\/login/)
  await expect(page.locator('a[href*="/admin/collections/users"]').first()).toBeVisible({
    timeout: 30_000,
  })
  const session = await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { email: string; roles: string[] } }
  expect(body.user.email).toBe(email)
  expect(body.user.roles).toContain('admin')

  // Demote so later specs on the shared server see a plain user.
  const revert = await adminContext(browser, baseURL)
  try {
    const revertPage = await revert.newPage()
    await gotoSettled(revertPage, '/admin')
    const demoted = await revertPage.evaluate(async (id: string) => {
      const response = await fetch(`/api/users/${id}`, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ roles: ['user'] }),
      })
      return response.status
    }, userId)
    expect(demoted).toBe(200)
  } finally {
    await revert.close()
  }
})

test('a passwordless user signs in through the view’s magic-link form (#157)', async ({
  page,
  browser,
  baseURL,
}) => {
  // The bock shape (#157): a verified provider account signs into the
  // admin through the view's alternative-methods form. Any address can
  // REQUEST a link, but only a known, verified account gets a usable
  // session — so register + verify one first. Like the test above, it
  // is promoted to `admin` (the panel refuses plain users), and demoted
  // afterwards so later specs on the shared server see a plain user.
  const email = `e2e-admin-magiclink-${Date.now()}@example.com`
  const userId = await signUpVerified(page.request, email)
  const admin = await adminContext(browser, baseURL)
  try {
    const adminPage = await admin.newPage()
    await gotoSettled(adminPage, '/admin')
    const patched = await adminPage.evaluate(async (id: string) => {
      const response = await fetch(`/api/users/${id}`, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ roles: ['admin'] }),
      })
      return { status: response.status, body: await response.text() }
    }, userId)
    expect(patched.status, `promote PATCH: ${patched.body}`).toBe(200)
  } finally {
    await admin.close()
  }

  // Signed out, then the magic-link form: the section renders because
  // the engine installs the magic-link plugin; submitting swaps the
  // form for the sent state (a 200 leaks nothing about the address).
  await page.context().clearCookies()
  await gotoSettled(page, '/admin/login')
  const magicForm = page.locator('form', { hasText: 'Continue' })
  await expect(magicForm).toBeVisible()
  await magicForm.getByLabel(/email/i).fill(email)
  await magicForm.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect(page.getByText(/check your email/i)).toBeVisible()

  // The emailed link lands back in the admin panel authenticated.
  let url: string | undefined
  await expect
    .poll(
      async () => {
        const response = await page.request.get(
          `/api/dev-mailbox?email=${encodeURIComponent(email)}`
        )
        expect(response.ok()).toBe(true)
        const body = (await response.json()) as { messages: { kind: string; url?: string }[] }
        url = body.messages.find((entry) => entry.kind === 'magic-link')?.url
        return url
      },
      { timeout: 30_000 }
    )
    .not.toBeUndefined()
  await page.goto(url as string)
  await expect(page).not.toHaveURL(/\/admin\/login/)
  await expect(page.locator('a[href*="/admin/collections/users"]').first()).toBeVisible({
    timeout: 30_000,
  })
  const session = await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { email: string } }
  expect(body.user.email).toBe(email)

  const revert = await adminContext(browser, baseURL)
  try {
    const revertPage = await revert.newPage()
    await gotoSettled(revertPage, '/admin')
    const demoted = await revertPage.evaluate(async (id: string) => {
      const response = await fetch(`/api/users/${id}`, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ roles: ['user'] }),
      })
      return response.status
    }, userId)
    expect(demoted).toBe(200)
  } finally {
    await revert.close()
  }
})
