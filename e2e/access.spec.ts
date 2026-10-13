import { expect, test, type Browser, type Page } from '@playwright/test'
import { DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD } from './dev-admin.js'

/**
 * Injected-field access defaults: a plain,
 * verified, self-registered user cannot grant themselves roles,
 * cannot reach the admin panel, and cannot read operator-facing
 * fields — while role managers keep full access. Pure-API specs:
 * the behaviour is HTTP-visible on every example and adapter.
 */

const password = 'e2e-test-password-1'

async function signUpVerified(
  request: APIRequestContext,
  email: string
): Promise<{ id: string; roles: string[] }> {
  const signup = await request.post('/api/auth/sign-up/email', {
    data: { name: email, email, password },
  })
  expect(signup.ok()).toBe(true)
  const stamped = await request.post('/api/dev-auto-verify', { data: { email } })
  expect(stamped.ok()).toBe(true)
  const session = await request.get('/api/auth-link/session')
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { id: string; email: string; roles: string[] } }
  return { id: body.user.id, roles: body.user.roles }
}

type AdminResponse = { status: number; body: unknown }

/**
 * REST calls signed in as the seeded admin (role manager), executed
 * inside an admin-panel page. Two Payload realities make a bare HTTP
 * client unusable here: the session cookie carries value-carrying
 * flag spellings (`Secure=false`, `HttpOnly=true`) that strict
 * clients file as secure and withhold on plain http, and mutating
 * requests without an `Origin` header fail the CSRF check. Running
 * `fetch` in the page fixes both — the browser parses the cookie and
 * stamps the origin — and the page itself proves authentication via
 * the real admin login form (the pattern users-admin.spec.ts keeps).
 */
async function adminRequest(
  baseURL: string | undefined,
  browser: Browser
): Promise<{ call: (method: string, path: string, body?: unknown) => Promise<AdminResponse>; close: () => Promise<void> }> {
  const context = await browser.newContext({ baseURL: baseURL ?? undefined })
  const page: Page = await context.newPage()
  await page.goto('/admin/login')
  await page.getByLabel(/email/i).fill(DEV_ADMIN_EMAIL)
  await page.getByRole('textbox', { name: /password/i }).fill(DEV_ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Login', exact: true }).click()
  await page.waitForURL('**/admin', { timeout: 15_000 })
  return {
    async call(method, path, body) {
      const result = await page.evaluate(
        async ({ method, path, body }) => {
          const response = await fetch(path, {
            method,
            headers: body === undefined ? {} : { 'content-type': 'application/json' },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          })
          let parsed: unknown = null
          try {
            parsed = await response.json()
          } catch {
            parsed = null
          }
          return { status: response.status, body: parsed }
        },
        { method, path, body }
      )
      return result
    },
    close: () => context.close(),
  }
}

test('a plain user cannot grant themselves roles', async ({ page }) => {
  const api = page.request
  const email = `e2e-esc-1-${Date.now()}@example.com`
  const user = await signUpVerified(api, email)

  // The advisory exploit: PATCH the own document's roles.
  const attempt = await api.patch(`/api/users/${user.id}`, {
    data: { roles: ['admin'] },
  })
  // Payload strips a field the caller cannot write; whatever the
  // status, the stored roles must not move.
  const body = (await attempt.json().catch(() => ({}))) as { doc?: { roles?: string[] } }
  expect(body.doc?.roles).not.toEqual(['admin'])

  const after = await api.get('/api/auth-link/session')
  expect(after.ok()).toBe(true)
  const session = (await after.json()) as { user: { roles: string[] } }
  expect(session.user.roles).toEqual(['user'])
})

test('a plain user is not an admin-panel user', async ({ page }) => {
  const api = page.request
  const email = `e2e-esc-2-${Date.now()}@example.com`
  await signUpVerified(api, email)

  const access = await api.get('/api/access')
  expect(access.ok()).toBe(true)
  const perms = (await access.json()) as {
    canAccessAdmin?: boolean
    collections: { users: { fields: Record<string, unknown> } }
  }
  // 3.90 serves canAccessAdmin through the admin routes only; the
  // REST map must at least carry no governing grant for the user.
  expect(perms.canAccessAdmin === true).toBe(false)
  expect(perms.collections.users?.fields?.roles).toBeUndefined()
})

test('a plain user cannot read operator-facing fields of anyone', async ({ page }) => {
  const api = page.request
  const email = `e2e-esc-3-${Date.now()}@example.com`
  const user = await signUpVerified(api, email)

  // The admin parks operator data on the fresh user.
  const browser = page.context().browser()
  if (browser === null) {
    throw new Error('access.spec needs a browser')
  }
  const admin = await adminRequest(test.info().project.use.baseURL, browser)
  const stamped = await admin.call('PATCH', `/api/users/${user.id}`, {
    suspendReason: 'internal note: fraud investigation',
  })
  expect(stamped.status).toBe(200)
  await admin.close()

  // The plain user's own document hides the operator fields; other
  // rows carry neither identities nor operator fields.
  const me = await api.get(`/api/users/${user.id}`)
  expect(me.ok()).toBe(true)
  const meDoc = (await me.json()) as Record<string, unknown>
  expect(meDoc).not.toHaveProperty('suspendReason')
  expect(meDoc).not.toHaveProperty('suspendedUntil')
  expect(Array.isArray(meDoc.roles)).toBe(true)

  const list = await api.get('/api/users?depth=0&limit=10')
  expect(list.ok()).toBe(true)
  const docs = (await list.json()) as { docs: Array<Record<string, unknown>> }
  expect(docs.docs.length).toBeGreaterThan(0)
  for (const doc of docs.docs) {
    expect(doc).not.toHaveProperty('suspendReason')
    expect(doc).not.toHaveProperty('suspendedUntil')
    const identities = doc.identities
    expect(identities === undefined || (Array.isArray(identities) && identities.length === 0)).toBe(
      true
    )
  }
})

test('a role manager can still edit roles and read operator fields', async ({ page }) => {
  const api = page.request
  const email = `e2e-esc-4-${Date.now()}@example.com`
  const user = await signUpVerified(api, email)
  const browser = page.context().browser()
  if (browser === null) {
    throw new Error('access.spec needs a browser')
  }
  const admin = await adminRequest(test.info().project.use.baseURL, browser)

  const grant = await admin.call('PATCH', `/api/users/${user.id}`, { roles: ['admin'] })
  expect(grant.status).toBe(200)
  const doc = grant.body as { doc: { roles: string[] } }
  expect(doc.doc.roles).toEqual(['admin'])

  const list = await admin.call('GET', '/api/users?depth=0&limit=10')
  expect(list.status).toBe(200)
  const docs = (list.body as { docs: Array<Record<string, unknown>> }).docs
  const row = docs.find((entry) => String(entry.id) === String(user.id))
  expect(row?.roles).toEqual(['admin'])

  // Revert so later specs (shared server) see a plain user.
  const revert = await admin.call('PATCH', `/api/users/${user.id}`, { roles: ['user'] })
  expect(revert.status).toBe(200)
  await admin.close()
})
