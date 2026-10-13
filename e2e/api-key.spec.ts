import { expect, test } from '@playwright/test'

/**
 * API keys (@better-auth/api-key, issue #16): a declared satellite
 * model works end to end — create, then authenticate over the
 * `api-key` channel. Key sessions carry the owner's Payload roles, so
 * an admin's key is an admin credential; `requireMfaForRoles` treats
 * them like any session without MFA proof (key sessions report
 * `assurance.mfa: false`, so an MFA-gated role stays withheld).
 */
const password = 'e2e-test-password-1'

test('an API key authenticates the api-key channel end to end', async ({ page }) => {
  const api = page.request
  const email = `e2e-apikey-${Date.now()}@example.com`
  const signup = await api.post('/api/auth/sign-up/email', {
    data: { name: email, email, password },
  })
  expect(signup.ok()).toBe(true)
  const stamped = await api.post('/api/dev-auto-verify', { data: { email } })
  expect(stamped.ok()).toBe(true)

  // Create the key through BA's own endpoint. The call is
  // cookie-authenticated, so BA's CSRF check requires the origin.
  const baseURL = test.info().project.use.baseURL ?? ''
  const created = await api.post('/api/auth/api-key/create', {
    headers: { origin: baseURL },
    data: { name: 'e2e key' },
  })
  expect(created.ok()).toBe(true)
  const { key } = (await created.json()) as { key?: string }
  expect(key ?? '').toMatch(/^bock_/)

  // The key resolves through the plugin's session endpoint...
  const session = await api.get('/api/auth-link/session', {
    headers: { 'x-api-key': key ?? '' },
  })
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as { user: { email: string; roles: string[] } }
  expect(body.user.email).toBe(email)
  expect(body.user.roles).toEqual(['user'])

  // ...and Payload REST sees the user behind it.
  const me = await api.get('/api/users/me', { headers: { 'x-api-key': key ?? '' } })
  expect(me.ok()).toBe(true)
  const meDoc = (await me.json()) as { user: { email: string } | null }
  expect(meDoc.user?.email).toBe(email)

  // An invalid key authenticates nothing.
  const invalid = await api.get('/api/auth-link/session', {
    headers: { 'x-api-key': 'bock_invalid' },
  })
  expect(invalid.status()).toBe(401)
})
