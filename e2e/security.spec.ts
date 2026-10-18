import { expect, test, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { gotoOwn, RETRY_ON_RESET, toggleToSignUp } from './helpers.js'
import { totp } from './totp.js'

/**
 * Account security (CAP-5/6): TOTP enrollment flips the session's
 * mapped assurance to `mfa: true`; passkeys register and sign in
 * through a CDP virtual authenticator (Chromium only — WebAuthn
 * automation has no cross-browser equivalent here).
 */
const password = 'e2e-test-password-1'
let counter = 0

function uniqueEmail(tag: string): string {
  counter += 1
  return `security-${tag}-${Date.now()}-${counter}@example.com`
}

async function signUp(page: Page, email: string): Promise<void> {
  await gotoOwn(page, '/sign-in')
  await toggleToSignUp(page)
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill(password)
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
}

async function signOut(page: Page): Promise<void> {
  await page.request.delete('/api/auth-link/session', {
    headers: { 'x-auth-link-csrf': '1' },
  })
  await page.context().clearCookies()
}

test('TOTP verification records a step-up and flips assurance to mfa:true', async ({ page }) => {
  const email = uniqueEmail('totp')
  await signUp(page, email)
  const before = (await (
    await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  ).json()) as {
    user: { assurance?: { mfa: unknown } }
  }
  expect(before.user.assurance?.mfa).not.toBe(true)

  // The MFA-gated route bounces to enrollment before MFA exists.
  await gotoOwn(page, '/mfa-only')
  await expect(page.getByTestId('mfa-granted')).toHaveCount(0)
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })

  await page.getByLabel(/current password/i).fill(password)
  await page.getByRole('button', { name: /set up two-factor/i }).click()
  const secretText = await page.getByTestId('totp-secret').textContent()
  const secret = /([A-Z2-7]{16,})/i.exec(secretText ?? '')?.[1]
  if (secret === undefined) {
    throw new Error(`no TOTP secret shown (got: ${secretText ?? 'nothing'})`)
  }
  await page.getByLabel(/two-factor code/i).fill(totp(secret))
  // The page verifies THROUGH the app's step-up route (server-side
  // re-verification + a minted session with the vouched proof), so the
  // session records the method.
  await page.getByRole('button', { name: /verify two-factor code/i }).click()
  await expect(page.getByRole('status')).toContainText(/two-factor authentication is on/i, {
    timeout: 30_000,
  })

  const after = (await (
    await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  ).json()) as {
    user: { assurance?: { mfa: unknown } }
  }
  expect(after.user.assurance?.mfa).toBe(true)

  // …and the same route now serves its content.
  await gotoOwn(page, '/mfa-only')
  await expect(page.getByTestId('mfa-granted')).toContainText(email, { timeout: 30_000 })
})

test('suspending a user in Payload bounces their next session read (CAP-7)', async ({
  page,
  browser,
  baseURL,
}) => {
  const email = uniqueEmail('suspend')
  await signUp(page, email)
  const session = (await (
    await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  ).json()) as {
    user: { id: string }
  }
  const admin = await adminContext(browser, baseURL)
  try {
    // In-browser fetch from the admin origin: carries the login cookie
    // and same-origin headers exactly like the Payload admin UI (a
    // bare API-client PATCH fails Payload's CSRF check).
    const adminPage = await admin.newPage()
    await adminPage.goto('/admin')
    const suspendedUntil = new Date(Date.now() + 3600_000).toISOString()
    const patched = await adminPage.evaluate(
      async ({ id, until }: { id: string; until: string }) => {
        const response = await fetch(`/api/users/${id}`, {
          method: 'PATCH',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ suspendedUntil: until, suspendReason: 'e2e validation' }),
        })
        return { status: response.status, body: await response.text() }
      },
      { id: String(session.user.id), until: suspendedUntil }
    )
    expect(patched.status, `suspend PATCH: ${patched.body}`).toBe(200)
  } finally {
    await admin.close()
  }
  // The very next verification refuses: endpoint 401, account signed out.
  const refused = await page.request.get('/api/auth-link/session', RETRY_ON_RESET)
  expect(refused.status()).toBe(401)
  await gotoOwn(page, '/account')
  await expect(page.getByTestId('account-email')).toHaveCount(0)
})

test('passkey registers and signs in (virtual authenticator)', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'virtual authenticators are Chromium/CDP only')
  const email = uniqueEmail('passkey')
  const client = await page.context().newCDPSession(page)
  await client.send('WebAuthn.enable')
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  })

  await signUp(page, email)
  await page.getByRole('button', { name: /add a passkey/i }).click()
  await expect(page.getByRole('status')).toContainText(/passkey added/i, { timeout: 30_000 })

  await signOut(page)
  await gotoOwn(page, '/sign-in/passwordless')
  await page.getByRole('button', { name: /sign in with a passkey/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
})
