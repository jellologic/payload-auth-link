import { expect, test, type Browser, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { RETRY_ON_RESET } from './helpers.js'

/**
 * Local-strategy account controls (GHSA-f4hj): suspension is enforced
 * on EVERY strategy at request time, provider-linked documents are
 * provider-owned (no self-service local credentials), and operator
 * accounts keep theirs. The MFA-policy projection for local sessions
 * is pinned by the integration credential-path matrix (the examples
 * carry Auth.js, which cannot honestly declare the `mfa` capability,
 * so the policy cannot be configured here).
 *
 * Payload's session cookie carries value-carrying flag spellings that
 * strict API clients withhold on plain http, so every local-credential
 * flow runs as same-origin `fetch` inside a page. Admin calls share
 * the global-setup admin login (`admin-session.ts`): concurrent admin
 * logins race on Payload's per-user sessions array and drop one
 * another's session.
 */

type AdminResponse = { status: number; body: unknown }

async function adminRequest(
  baseURL: string | undefined,
  browser: Browser
): Promise<{
  call: (method: string, path: string, body?: unknown) => Promise<AdminResponse>
  close: () => Promise<void>
}> {
  const context = await adminContext(browser, baseURL)
  const page: Page = await context.newPage()
  await page.goto('/admin')
  return {
    async call(method, path, body) {
      return page.evaluate(
        async ({ method, path, body }) => {
          const response = await fetch(path, {
            method,
            headers: body === undefined ? {} : { 'content-type': 'application/json' },
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
    },
    close: () => context.close(),
  }
}

/**
 * A plain browser context whose same-origin `fetch` carries Payload's
 * local-strategy session cookie: the channel a suspended user's
 * pre-existing local JWT lives on.
 */
async function localSession(
  baseURL: string | undefined,
  browser: Browser,
  email: string,
  password: string
): Promise<{
  call: (method: string, path: string, body?: unknown) => Promise<AdminResponse>
  loginStatus: number
  close: () => Promise<void>
}> {
  const context = await browser.newContext({
    ...(baseURL === undefined ? {} : { baseURL }),
  })
  const page: Page = await context.newPage()
  await page.goto('/')
  const loginStatus = await page.evaluate(
    async ({ email, password }) => {
      const response = await fetch('/api/users/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      return response.status
    },
    { email, password }
  )
  return {
    loginStatus,
    async call(method, path, body) {
      return page.evaluate(
        async ({ method, path, body }) => {
          const response = await fetch(path, {
            method,
            headers: body === undefined ? {} : { 'content-type': 'application/json' },
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
    },
    close: () => context.close(),
  }
}

test('a suspended operator is locked out on every credential they hold', async ({ browser }) => {
  const baseURL = test.info().project.use.baseURL
  const admin = await adminRequest(baseURL, browser)
  const email = `e2e-suspend-${Date.now()}@example.com`
  const password = 'OperatorKnows-1'

  // The role manager creates an operator account (no linked
  // identities): local sign-in and the reset flow are theirs to use.
  const created = await admin.call('POST', '/api/users', {
    email,
    password,
    roles: ['user'],
  })
  expect(created.status, `operator create failed: ${JSON.stringify(created.body)}`).toBe(201)
  const id = String((created.body as { doc: { id: string | number } }).doc.id)

  const session = await localSession(baseURL, browser, email, password)
  expect(session.loginStatus).toBe(200)
  const before = await session.call('POST', '/api/pages', { title: `page-${Date.now()}` })
  expect(before.status).toBe(201)

  // The suspension lands AFTER the local JWT exists.
  const suspend = await admin.call('PATCH', `/api/users/${id}`, {
    suspendedUntil: new Date(Date.now() + 86_400_000).toISOString(),
    suspendReason: 'e2e',
  })
  expect(suspend.status).toBe(200)

  // The pre-existing local JWT resolves no user from the very next
  // request on (GHSA-mjvh): it is anonymous everywhere — users
  // operations, host collections, and refresh alike.
  const write = await session.call('POST', '/api/pages', { title: 'nope' })
  expect(write.status).toBe(403)
  const self = await session.call('PATCH', `/api/users/${id}`, {})
  expect(self.status).toBe(403)
  const refreshed = await session.call('POST', '/api/users/refresh-token', {})
  expect(refreshed.status).toBe(403)

  // A fresh local login is refused too.
  const relogin = await localSession(baseURL, browser, email, password)
  expect(relogin.loginStatus).toBe(401)

  await session.close()
  await relogin.close()
  await admin.close()
})

test('forgot/reset on a provider-linked document yields no usable password', async ({
  browser,
  page,
}) => {
  const baseURL = test.info().project.use.baseURL
  const api = page.request
  const email = `e2e-owned-${Date.now()}@example.com`
  const signup = await api.post('/api/auth/sign-up/email', {
    data: { name: email, email, password: 'e2e-test-password-1' },
  })
  expect(signup.ok()).toBe(true)
  await api.post('/api/dev-auto-verify', { data: { email } })
  const linked = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(linked.ok()).toBe(true)

  // The self-service reset path is closed for provider-owned
  // documents: no token is ever issued.
  const forgot = await api.post('/api/users/forgot-password', {
    headers: { origin: baseURL ?? '' },
    data: { email },
  })
  expect(forgot.status()).toBe(403)

  // Local sign-in is refused for the linked document: it holds no
  // local password anyone knows (the reset path above is closed), so a
  // guess fails Payload's credential check with 401 before the
  // provider-owned `beforeLogin` refusal (403, which needs the right
  // password; covered by the engine suites) is ever reached.
  const local = await localSession(baseURL, browser, email, 'AnyGuessKnows-1')
  expect(local.loginStatus).toBe(401)
  await local.close()
})

test('an operator account keeps the local credential and the reset flow', async ({
  browser,
  page,
}) => {
  const baseURL = test.info().project.use.baseURL
  const api = page.request
  const admin = await adminRequest(baseURL, browser)
  const email = `e2e-operator-${Date.now()}@example.com`
  const password = 'OperatorKnows-2'
  const created = await admin.call('POST', '/api/users', {
    email,
    password,
    roles: ['user'],
  })
  expect(created.status, `operator create failed: ${JSON.stringify(created.body)}`).toBe(201)

  const session = await localSession(baseURL, browser, email, password)
  expect(session.loginStatus).toBe(200)
  await session.close()

  // The password recovery flow stays available for operator accounts
  // (no linked identities): forgot-password answers 200.
  const forgot = await api.post('/api/users/forgot-password', {
    headers: { origin: baseURL ?? '' },
    data: { email },
  })
  expect(forgot.status()).toBe(200)
  await admin.close()
})
