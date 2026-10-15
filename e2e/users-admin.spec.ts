import { expect, test } from '@playwright/test'
import { DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD } from './dev-admin.js'
import {
  gotoOwn,
  gotoSettled,
  listCell,
  listTable,
  seededAdminCell,
  toggleToSignUp,
} from './helpers.js'

test('admin users show roles and linked identities', async ({ page }) => {
  const email = `e2e-admin-${Date.now()}@example.com`
  // Provision a provider user through the real sign-up flow; the Payload
  // user document (roles + linked identity) is created just-in-time.
  await gotoOwn(page, '/sign-in')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill('e2e-test-password-1')
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  const session = await page.request.get('/api/auth-link/session')
  const { user } = (await session.json()) as { user: { id: string | number } }

  // Inspect it from the Payload admin as the seeded local admin. The
  // provider session doubles as Payload auth (by design), so clear it
  // first — otherwise /admin/login bounces straight to the dashboard.
  await page.context().clearCookies()
  await gotoSettled(page, '/admin/login')
  // The provider-backed login view (#55/#72) renders two forms; the
  // seeded operator is unlinked, so it signs in through the
  // break-glass local form.
  const localForm = page.locator('form', { hasText: 'Break-glass local sign-in' })
  await localForm.getByLabel(/email/i).fill(DEV_ADMIN_EMAIL)
  await localForm.getByRole('textbox', { name: /password/i }).fill(DEV_ADMIN_PASSWORD)
  await localForm.getByRole('button', { name: 'Sign in locally', exact: true }).click()
  await page.waitForURL('**/admin', { timeout: 15000 })
  // Parallel specs (and earlier engines sharing the database) provision
  // many users: pin a page size that keeps both the seeded admin
  // (oldest) and our user (newest) on page one.
  await gotoSettled(page, '/admin/collections/users?limit=500')
  // Split wait: the table shell first (page-load diagnosis), then the
  // seeded admin row (data diagnosis). The list query is occasionally
  // slow on cold Postgres, so the data row gets an explicit readiness
  // probe — reload until it renders, within a stated budget — rather
  // than leaning on CI retries (the spec must pass with retries off).
  await expect(listTable(page)).toBeVisible({ timeout: 30_000 })
  await expect(async () => {
    if (!(await seededAdminCell(page).isVisible())) {
      await page.reload()
    }
    await expect(seededAdminCell(page)).toBeVisible({ timeout: 10_000 })
  }).toPass({ timeout: 60_000 })
  // Parallel workers share one database, so scope to our user's row by
  // its document link (v3 names rows `ID: <id>`; v4 names them by row
  // number — the doc href is the stable handle on both).
  const idLink = page.locator(`a[href$="/admin/collections/users/${user.id}"]`)
  const row = page.getByRole('row').filter({ has: idLink })
  await expect(row).toBeVisible()
  await expect(listCell(row, 'user')).toBeVisible()
  await expect(listCell(row, '1 Identity')).toBeVisible()
  // Follow the row's own link by URL, not by click: the Payload admin
  // list is server-rendered and WebKit can accept a click before the
  // list hydrates, silently dropping the navigation (seen in CI).
  const href = await idLink.first().getAttribute('href')
  expect(href).not.toBeNull()
  await gotoSettled(page, href ?? '')
  await expect(page.getByText(`better-auth · ${email}`)).toBeVisible({ timeout: 30_000 })
})
