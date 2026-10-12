import { AxeBuilder } from '@axe-core/playwright'
import { expect, test, type TestInfo } from '@playwright/test'
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

/**
 * Upstream snapshot for the FULL admin users page (Payload's own chrome):
 * axe rule id → node count observed on 2026-10-12 (row-select
 * checkboxes excluded, so counts do not scale with rows). The page must report
 * no rule outside this set and no more nodes per rule, so a new upstream
 * regression (or anything we add to the admin) fails here instead of
 * hiding behind the `tbody` scoping above. Fixes upstream (fewer nodes,
 * vanished rules) pass; shrink the snapshot when they land.
 */
const upstreamAdminViolations: Record<3 | 4, Readonly<Record<string, number>>> = {
  // Payload v3: sort-label contrast per column, unlabeled select-all and
  // search input, duplicated/missing landmarks.
  3: {
    'color-contrast': 4,
    'label-title-only': 1,
    label: 1,
    'landmark-no-duplicate-banner': 1,
    'landmark-one-main': 1,
    'landmark-unique': 1,
    region: 8,
  },
  // Payload v4 (4.0.0-beta line): Gecko flags contrast on fixed chrome
  // (nav group label, Create New, column headers, pagination); Chromium
  // and WebKit report none. Counts are the max across engines.
  4: { 'color-contrast': 8 },
}

function payloadMajor(testInfo: TestInfo): 3 | 4 {
  const major: unknown = testInfo.config.metadata['payloadMajor']
  if (major !== 3 && major !== 4) {
    throw new Error('playwright config must declare metadata.payloadMajor (3 or 4)')
  }
  return major
}

test('admin users page reports nothing beyond the upstream snapshot', async ({
  browser,
  baseURL,
}, testInfo) => {
  const allowed = upstreamAdminViolations[payloadMajor(testInfo)]
  const admin = await adminContext(browser, baseURL)
  const page = await admin.newPage()
  await gotoSettled(page, '/admin/collections/users?sort=createdAt')
  await expect(seededAdminCell(page)).toBeVisible()
  // Per-row upstream chrome, triaged in the tbody test above, scales
  // with the row count: unlabeled row-select checkboxes (v3) and the v4
  // ID-cell `.id-label` contrast (flagged by Gecko, not Chromium).
  // Excluding both keeps this snapshot independent of how many users
  // exist and of the engine.
  const results = await new AxeBuilder({ page })
    .exclude('tbody input[type="checkbox"]')
    .exclude('.id-label')
    .analyze()
  const beyond = results.violations
    .filter((violation) => violation.nodes.length > (allowed[violation.id] ?? 0))
    .map((violation) => ({
      rule: violation.id,
      nodes: violation.nodes.length,
      allowed: allowed[violation.id] ?? 0,
      targets: violation.nodes.map((node) => node.target.join(' ')),
    }))
  expect(beyond).toEqual([])
  await admin.close()
})
