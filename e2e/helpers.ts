import { expect, type APIRequestContext, type Locator, type Page } from '@playwright/test'

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

/** Password every self-registered e2e user signs up with. */
export const E2E_PASSWORD = 'e2e-test-password-1'

/**
 * Sign a fresh user up through Better Auth's email+password route,
 * stamp them verified (the example's dev-only route — the plugin
 * provisions verified identities only), and return the Payload user id
 * plus the Better Auth user id (what BA's admin endpoints take).
 */
export async function signUpVerified(
  request: APIRequestContext,
  email: string
): Promise<{ userId: string; providerUserId: string }> {
  const signup = await request.post('/api/auth/sign-up/email', {
    data: { name: email, email, password: E2E_PASSWORD },
  })
  expect(signup.ok(), `sign-up ${email}: ${String(signup.status())}`).toBe(true)
  const created = (await signup.json()) as { user?: { id?: unknown } }
  const providerUserId = created.user?.id
  if (typeof providerUserId !== 'string') {
    throw new Error(`sign-up for ${email} returned no provider user id`)
  }
  const stamped = await request.post('/api/dev-auto-verify', { data: { email } })
  expect(stamped.ok()).toBe(true)
  const session = await request.get('/api/auth-link/session')
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { id: string | number; email: string } }
  expect(body.user.email).toBe(email)
  return { userId: String(body.user.id), providerUserId }
}

export type FetchResult = { status: number; body: unknown }

/**
 * `fetch` from inside the page: the browser attaches its own cookies,
 * stamps a same-origin `Origin`, and applies every `Set-Cookie` the
 * response sends (deletions included — WebKit's `page.request` can
 * keep a cookie a response expires). The page must already be on the
 * app's origin.
 */
export async function pageFetch(
  page: Page,
  method: string,
  path: string,
  body?: unknown
): Promise<FetchResult> {
  return page.evaluate(
    async ({ method, path, body }) => {
      const response = await fetch(path, {
        method,
        credentials: 'same-origin',
        headers: {
          'x-auth-link-csrf': '1',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      })
      let parsed: unknown
      try {
        parsed = await response.json()
      } catch {
        parsed = null
      }
      return { status: response.status, body: parsed }
    },
    { method, path, body }
  )
}

/**
 * Set a user's Payload roles as the seeded admin (role manager), from
 * the shared run-level admin session (`admin-session.ts`) — never a
 * fresh admin login, which would race other specs' sessions.
 */
export async function setRolesAsAdmin(
  adminPage: Page,
  userId: string,
  roles: readonly string[]
): Promise<void> {
  const patched = await pageFetch(adminPage, 'PATCH', `/api/users/${userId}`, { roles })
  expect(patched.status, `set roles ${roles.join(',')}: ${JSON.stringify(patched.body)}`).toBe(200)
}
