import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { gotoOwn, gotoSettled, seededAdminCell, toggleToSignUp } from './helpers.js'

/**
 * Accessibility floor. Our own pages (both sign-in variants, account)
 * must report zero violations on a full-page scan. The Payload admin
 * is Payload's surface: a full-page scan there reports upstream
 * violations we cannot fix (sort-label color-contrast on every
 * column, page landmarks, native inputs), so the admin test scopes
 * to the users table body — our rendered data cells — excluding only
 * Payload's own chrome: the row-select checkbox, and (v4 only) the
 * ID cell's `.id-label`, whose prefix contrast (#7b7b7b on #f5f5f5,
 * 3.88) fails upstream of us. Anything OUR code renders must be
 * clean; the scoping is triaged and documented, not waived.
 */
test('sign-in pages have zero axe violations', async ({ page }) => {
  for (const path of ['/sign-in', '/sign-in-authjs']) {
    await gotoOwn(page, path)
    const results = await new AxeBuilder({ page }).analyze()
    expect(results.violations).toEqual([])
  }
})

test('account page has zero axe violations when signed in', async ({ page }) => {
  const email = `e2e-axe-${Date.now()}@example.com`
  await gotoOwn(page, '/sign-in')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill('e2e-test-password-1')
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  const results = await new AxeBuilder({ page }).analyze()
  expect(results.violations).toEqual([])
})

test('admin users table body has zero axe violations', async ({ browser, baseURL }) => {
  // Shared run-level admin session (see admin-session.ts): no login here.
  const admin = await adminContext(browser, baseURL)
  const page = await admin.newPage()
  // Oldest first: the seeded admin stays on page one however many users
  // earlier specs (and earlier engines) provisioned.
  await gotoSettled(page, '/admin/collections/users?sort=createdAt')
  await expect(seededAdminCell(page)).toBeVisible()
  const results = await new AxeBuilder({ page })
    .include('tbody')
    .exclude('input[type="checkbox"]')
    // v4 ID-cell prefix label: upstream contrast failure, no-op on v3
    // (which renders no `.id-label`).
    .exclude('.id-label')
    .analyze()
  expect(results.violations).toEqual([])
})
