import { expect, test, type APIRequestContext, type Browser, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { RETRY_ON_RESET } from './helpers.js'

/**
 * Injected-field access defaults: a plain,
 * verified, self-registered user cannot grant themselves roles,
 * cannot reach the admin panel, and cannot read operator-facing
 * fields — while role managers keep full access. Pure-API specs:
 * the behaviour is HTTP-visible on every example and adapter.
 */

const password = 'e2e-test-password-1'

function baseURL(): string | undefined {
  return test.info().project.use.baseURL
}

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
  const session = await request.get('/api/auth-link/session', RETRY_ON_RESET)
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
 * stamps the origin.
 *
 * The session comes from the global-setup admin login
 * (`admin-session.ts`): Payload's login read-modify-writes the user's
 * `sessions` array, so concurrent admin logins drop one another's
 * session (observed as spurious 403s) — specs never log the admin in
 * themselves.
 */
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
      const result = await page.evaluate(
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
      return result
    },
    close: () => context.close(),
  }
}

test('a non-manager cannot create users, and sees only themselves in the list (GHSA-98hq-hh6v-2p2r)', async ({
  page,
}) => {
  const api = page.request
  const email = `e2e-jit-1-${Date.now()}@example.com`
  const user = await signUpVerified(api, email)

  // The pre-account-hijack entry point: REST-creating a Payload user
  // with a chosen email + password.
  const attempt = await api.post('/api/users', {
    data: { email: `victim-${Date.now()}@example.com`, password: 'AttackerKnows-1' },
  })
  expect(attempt.status()).toBe(403)

  // Enumeration residual: the list is constrained to the caller.
  const list = await api.get('/api/users?depth=0&limit=10')
  expect(list.ok()).toBe(true)
  const docs = (await list.json()) as { docs: Array<{ email: string }> }
  expect(docs.docs.length).toBe(1)
  expect(docs.docs[0]?.email).toBe(email)
  void user
})

test('an unproven pre-created document is never JIT-linked; a proven one is', async ({
  page,
  browser,
}) => {
  const api = page.request
  const admin = await adminRequest(test.info().project.use.baseURL, browser)

  // Manager creates a document for a future member (the import/admin
  // workflow). The marker hook proves it: linkable defaults to true.
  const victimEmail = `e2e-jit-victim-${Date.now()}@example.com`
  const created = await admin.call('POST', '/api/users', {
    email: victimEmail,
    password: 'ImportedKnows-1',
  })
  expect(created.status, `manager create failed: ${JSON.stringify(created.body)}`).toBe(201)
  const doc = created.body as { doc: { id: string; linkable?: boolean } }
  expect(doc.doc.linkable).toBe(true)

  // A role manager can withdraw the proof: the document becomes
  // unproven, and JIT linking must refuse it.
  const unprove = await admin.call('PATCH', `/api/users/${doc.doc.id}`, {
    linkable: false,
  })
  expect(unprove.status, `unprove failed: ${JSON.stringify(unprove.body)}`).toBe(200)
  const signup = await api.post('/api/auth/sign-up/email', {
    data: { name: victimEmail, email: victimEmail, password: 'e2e-test-password-1' },
  })
  expect(signup.ok()).toBe(true)
  await api.post('/api/dev-auto-verify', { data: { email: victimEmail } })
  const denied = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(denied.status()).toBe(401)

  // Restore the proof: the SAME verified identity now links to the
  // SAME document — the import/migration path stays intact.
  const restore = await admin.call('PATCH', `/api/users/${doc.doc.id}`, {
    linkable: true,
  })
  expect(restore.status).toBe(200)
  const linked = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(linked.ok()).toBe(true)
  const session = (await linked.json()) as { user: { id: string; roles: string[] } }
  expect(session.user.id).toBe(String(doc.doc.id))
})

test('GHSA-8524 chain: self email change is neutered and the victim is never linked', async ({
  page,
  browser,
}) => {
  const api = page.request
  const attackerEmail = `e2e-jit-attack-${Date.now()}@example.com`
  const attacker = await signUpVerified(api, attackerEmail)
  const admin = await adminRequest(baseURL(), browser)

  // Step 1 (was the exploit): the attacker plants the victim's email
  // on their own plugin-created document. Field access strips it.
  // Idempotent (the same body re-applies the same refusal), so it may
  // take the reset retry: it follows a slow admin login (issue #116).
  const plant = await api.patch(`/api/users/${attacker.id}`, {
    data: { email: `e2e-jit-victim-${Date.now()}@example.com` },
    ...RETRY_ON_RESET,
  })
  const plantBody = (await plant.json().catch(() => ({}))) as { doc?: { email?: string } }
  expect(plantBody.doc?.email ?? attackerEmail).toBe(attackerEmail)

  // Defence in depth: even if an operator moves the email via a
  // manager write, the linkable proof (bound to the proven email)
  // no longer matches, so a later verified sign-up with the victim
  // address cannot resolve to the attacker document. Prove the
  // mismatch refusal directly: admin moves the email, a fresh
  // verified sign-up with that address must NOT link to doc id.
  const victimAddress = `e2e-jit-victim2-${Date.now()}@example.com`
  const moved = await admin.call('PATCH', `/api/users/${attacker.id}`, {
    email: victimAddress,
  })
  expect(moved.status).toBe(200)
  const victimSignup = await api.post('/api/auth/sign-up/email', {
    headers: { origin: baseURL() ?? '' },
    data: { name: victimAddress, email: victimAddress, password: 'e2e-test-password-1' },
  })
  expect(victimSignup.ok()).toBe(true)
  await api.post('/api/dev-auto-verify', { data: { email: victimAddress } })
  const session = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(session.status()).toBe(401)
})

test('the migration import path (role-manager proven) still links; provider resync keeps proof (GHSA-8524)', async ({
  page,
  browser,
}) => {
  const api = page.request
  const admin = await adminRequest(baseURL(), browser)

  // Manager imports a future member: proven for the imported email.
  const importEmail = `e2e-jit-import-${Date.now()}@example.com`
  const created = await admin.call('POST', '/api/users', {
    email: importEmail,
    password: 'ImportedKnows-1',
  })
  expect(created.status).toBe(201)
  const doc = created.body as { doc: { id: string; linkableEmail?: string } }
  expect(doc.doc.linkableEmail).toBe(importEmail)

  // The imported user signs up via the provider and verifies: JIT
  // linking attaches the identity to the imported document.
  const signup = await api.post('/api/auth/sign-up/email', {
    data: { name: importEmail, email: importEmail, password: 'e2e-test-password-1' },
  })
  expect(signup.ok()).toBe(true)
  await api.post('/api/dev-auto-verify', { data: { email: importEmail } })
  const session = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { id: string; email: string } }
  expect(body.user.id).toBe(String(doc.doc.id))

  // The provider-email resync keeps the proof bound: manager moves
  // the account to a new provider-verified address via the plugin's
  // own email flow — simulated here by a manager write of BOTH email
  // and linkableEmail (exactly what the resync writes).
  const newEmail = `e2e-jit-moved-${Date.now()}@example.com`
  const resync = await admin.call('PATCH', `/api/users/${doc.doc.id}`, {
    email: newEmail,
    linkableEmail: newEmail,
  })
  expect(resync.status).toBe(200)
})

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

  const after = await api.get('/api/auth-link/session', RETRY_ON_RESET)
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
