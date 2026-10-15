import { expect, type Locator, type Page } from '@playwright/test'

/**
 * Navigate to one of our own pages and wait for first hydration (the
 * `HydratedMarker` in each example layout sets
 * `html[data-hydrated]`). SSR HTML accepts clicks before React
 * hydrates — a click in that window is silently lost — so every
 * navigation the test then clicks through must settle first. Only
 * first loads wait: client-side navigations keep the marker, and a
 * running React app is interactive by definition. Payload admin
 * navigations keep raw `page.goto` (Payload's surface, not ours).
 */
export async function gotoOwn(page: Page, path: string): Promise<void> {
  await gotoSettled(page, path)
  await expect(page.locator('html[data-hydrated="true"]')).toBeAttached()
}

/**
 * `page.goto` that tolerates WebKit's navigation races. WebKit aborts a
 * `goto` that collides with a navigation the app itself starts — the
 * post-sign-out redirect still settling ("Frame load interrupted"), or
 * a signed-out page bouncing to sign-in after `clearCookies()` ("is
 * interrupted by another navigation"); Chromium queues them. Gecko has
 * the same race with its own message ("NS_BINDING_ABORTED") — seen
 * when the provider login view's post-sign-in redirect is still
 * settling — so the same retries cover it. Retry those
 * engine-specific interruptions (up to twice), never other failures.
 * Use directly for Payload admin pages (no hydration marker).
 */
export async function gotoSettled(page: Page, path: string): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await page.goto(path)
      return
    } catch (error) {
      const interrupted =
        error instanceof Error &&
        (error.message.includes('Frame load interrupted') ||
          error.message.includes('is interrupted by another navigation') ||
          error.message.includes('NS_BINDING_ABORTED'))
      if (!interrupted || attempt >= 2) {
        throw error
      }
    }
  }
}

/**
 * Flip a sign-in form to sign-up mode, tolerating SSR/hydration skew.
 * Belt-and-braces behind `gotoOwn`: re-click until the flip is
 * observed, so even a lost click cannot wedge the flow. Harmless on
 * fast-hydrating frameworks, where the first click lands.
 */
/**
 * Payload version split, one locator: v3 collection lists render as
 * `table`/`cell`, v4 as `grid`/`gridcell` over the same `<table>`
 * markup. Both roles never co-occur, so the union is unambiguous.
 */
export function listTable(page: Page): Locator {
  return page.getByRole('table').or(page.getByRole('grid'))
}

/**
 * The seeded admin's own `admin` roles cell. Earlier specs (and earlier
 * engines in the sqlite matrix, which share one database) promote other
 * users to admin, so a bare `admin` cell is ambiguous. The list shows no
 * email column; the seeded admin is the only admin with no linked
 * identity (promoted users signed in through a provider).
 */
export function seededAdminCell(page: Page): Locator {
  const row = page
    .getByRole('row')
    .filter({ has: listCell(page, 'admin') })
    .filter({ has: listCell(page, '0 Identities') })
  return listCell(row, 'admin')
}

export function listCell(scope: Page | Locator, name: string | RegExp): Locator {
  return scope.getByRole('cell', { name }).or(scope.getByRole('gridcell', { name }))
}

export async function toggleToSignUp(page: Page): Promise<void> {
  await expect(async () => {
    const create = page.getByRole('button', { name: /create account/i })
    if ((await create.count()) === 0) {
      await page.getByRole('button', { name: /need an account/i }).click()
    }
    await expect(create).toBeVisible()
  }).toPass()
}
