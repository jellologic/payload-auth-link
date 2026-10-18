import { expect, test } from '@playwright/test'
import { RETRY_ON_RESET } from './helpers.js'

/**
 * Verification enforcement (SEC-2): the plugin provisions and links
 * users only from verified identities. This runs against the standard
 * examples (`requireEmailVerification: false`) ON PURPOSE: with
 * verification on, Better Auth withholds sessions from unverified
 * users entirely (signup returns `token: null`, sign-in 403s
 * `EMAIL_NOT_VERIFIED` — probed 2026-10-11), so no unverified
 * provider session can ever reach the plugin and the test would prove
 * Better Auth's gate instead of ours. OAuth providers (and any flow
 * yielding unverified sessions) are the real threat, modeled here by
 * signing up through the raw API — bypassing the form's local-only
 * dev stamp — and asserting the plugin 401s until verification lands.
 */
test('unverified provider sessions 401 until the email is verified', async ({ page }) => {
  const email = `e2e-unverified-${Date.now()}@example.com`
  const api = page.request

  // Raw signup: real provider session, unverified email (no stamp —
  // the form is bypassed, exactly like an unverified OAuth user).
  const signup = await api.post('/api/auth/sign-up/email', {
    data: { name: email, email, password: 'e2e-test-password-1' },
  })
  expect(signup.ok()).toBe(true)

  // Our gate: no provisioning from an unverified identity.
  const denied = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(denied.status()).toBe(401)

  // The builder verifies out-of-band (locally: the dev stamp route)
  // and the SAME session now links.
  const stamped = await api.post('/api/dev-auto-verify', { data: { email } })
  expect(stamped.ok()).toBe(true)
  const linked = await api.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(linked.ok()).toBe(true)
  const body = (await linked.json()) as { user: { email: string; roles: string[] } }
  expect(body.user.email).toBe(email)
  expect(body.user.roles).toEqual(['user'])
})
