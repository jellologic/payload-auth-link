import { expect, test, type APIRequestContext } from '@playwright/test'
import { RETRY_ON_RESET } from './helpers.js'

/**
 * Row 17 of docs/security-model.md: the plugin's session endpoint
 * (`DELETE /api/auth-link/session`) is a state-changing request on an
 * ambient cookie credential, so it requires CSRF proof — the
 * `x-auth-link-csrf: 1` header or a same-origin `Origin`. Without it
 * the request is refused (403) and the session survives.
 *
 * A fresh, self-registered user (never the shared seeded admin, whose
 * one-login-per-run session other specs depend on — see
 * `admin-session.ts`). Pure API: the behaviour is HTTP-visible on
 * every example and adapter.
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
  const body = (await session.json()) as { user: { email: string } }
  expect(body.user.email).toBe(email)
  return body.user.email
}

test('DELETE /api/auth-link/session without CSRF proof is 403 and the session survives (row 17)', async ({
  page,
}) => {
  const api = page.request
  const email = await signUpVerified(api, `e2e-csrf-${Date.now()}@example.com`)

  // No CSRF header and no Origin (Playwright's API client stamps none).
  const bare = await api.delete('/api/auth-link/session')
  expect(bare.status()).toBe(403)

  // A cross-site Origin is not proof either.
  const crossSite = await api.delete('/api/auth-link/session', {
    headers: { origin: 'https://attacker.example' },
  })
  expect(crossSite.status()).toBe(403)

  // Neither refused request touched the session.
  const alive = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(alive.status()).toBe(200)
  const body = (await alive.json()) as { user: { email: string } }
  expect(body.user.email).toBe(email)

  // With the CSRF header the same request signs out.
  const signedOut = await api.delete('/api/auth-link/session', {
    headers: { 'x-auth-link-csrf': '1' },
  })
  expect(signedOut.ok()).toBe(true)
  const after = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(after.status()).toBe(401)
})
