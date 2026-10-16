import { randomUUID } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import {
  E2E_PASSWORD,
  type FetchResult,
  gotoOwn,
  gotoSettled,
  pageFetch,
  setRolesAsAdmin,
  signUpVerified,
} from './helpers.js'
import { totp, wrongTotp } from './totp.js'

/**
 * `policies.requireMfaForRoles: ['auditor']` (CAP-6) on the
 * Better-Auth-only variant of examples/basic (playwright.mfa.config.ts).
 * The policy is a per-session projection: the stored role stays on the
 * Payload user, but a session without MFA proof is served WITHOUT it
 * (and flagged `mfaRequired`), so Payload access and `requireRoles`
 * both see it withheld. A Better Auth native two-factor sign-in records
 * the `two-factor` method on the fresh session, which proves MFA.
 */
type SessionBody = {
  user: {
    id: string | number
    roles: string[]
    mfaRequired?: boolean
    assurance?: { mfa: unknown }
  } | null
}

/** Unique across workers too (repeats and engines may run side by side). */
function uniqueEmail(): string {
  return `mfa-policy-${randomUUID()}@example.com`
}

async function readSession(page: Page): Promise<{ status: number; body: SessionBody | null }> {
  const result = await pageFetch(page, 'GET', '/api/auth-link/session')
  return {
    status: result.status,
    body: result.status === 200 ? (result.body as SessionBody) : null,
  }
}

async function expectWithheld(page: Page): Promise<void> {
  const session = await readSession(page)
  expect(session.status).toBe(200)
  expect(session.body?.user?.roles).not.toContain('auditor')
  expect(session.body?.user?.mfaRequired).toBe(true)
  expect(session.body?.user?.assurance?.mfa).not.toBe(true)
}

async function expectGranted(page: Page): Promise<void> {
  const session = await readSession(page)
  expect(session.status).toBe(200)
  expect(session.body?.user?.roles).toContain('auditor')
  expect(session.body?.user?.mfaRequired).not.toBe(true)
  expect(session.body?.user?.assurance?.mfa).toBe(true)
}

/**
 * Complete Better Auth's pending two-factor sign-in with a TOTP code.
 * Better Auth's `twoFactor()` caps `/two-factor/*` at 3 requests per
 * 10s per IP (enrollment already spent some), so a 429 is waited out
 * and retried with a fresh code; any other answer is returned as-is.
 */
async function verifyTotp(page: Page, code: () => string): Promise<FetchResult> {
  let result: FetchResult = { status: 0, body: null }
  await expect(async () => {
    result = await pageFetch(page, 'POST', '/api/auth/two-factor/verify-totp', { code: code() })
    expect(result.status, 'two-factor verify throttled').not.toBe(429)
  }).toPass({ intervals: [2_000], timeout: 30_000 })
  return result
}

/**
 * Click an account-page security button (after filling the code field
 * from `code`, when given) and return the status of the request it
 * makes to `path`, retrying while Better Auth throttles (429; see
 * {@link verifyTotp}).
 */
async function submitUnthrottled(
  page: Page,
  button: RegExp,
  path: string,
  code?: () => string
): Promise<number> {
  let status = 0
  await expect(async () => {
    if (code !== undefined) {
      await page.getByLabel(/two-factor code/i).fill(code())
    }
    const response = page.waitForResponse((candidate) => candidate.url().endsWith(path))
    await page.getByRole('button', { name: button }).click()
    status = (await response).status()
    expect(status, `${path} throttled`).not.toBe(429)
  }).toPass({ intervals: [2_000], timeout: 30_000 })
  return status
}

/** The gated page bounces a withheld session to the step-up prompt. */
async function expectPageDenied(page: Page): Promise<void> {
  await gotoOwn(page, '/auditor-only')
  await expect(page).toHaveURL(/\/account\?step-up=mfa/)
  await expect(page.getByTestId('auditor-granted')).toHaveCount(0)
}

test('auditor is withheld without MFA and granted after a password + TOTP sign-in', async ({
  page,
  browser,
  baseURL,
}) => {
  const email = uniqueEmail()

  const userId =
    await test.step('sign up and get the gated role from the seeded admin', async () => {
      await gotoOwn(page, '/')
      const { userId: id } = await signUpVerified(page.request, email)
      const admin = await adminContext(browser, baseURL)
      try {
        const adminPage = await admin.newPage()
        await gotoSettled(adminPage, '/admin')
        await setRolesAsAdmin(adminPage, id, ['user', 'auditor'])
      } finally {
        await admin.close()
      }
      return id
    })

  await test.step('a password-only session has the role withheld (mfaRequired)', async () => {
    await expectWithheld(page)
    await expectPageDenied(page)
  })

  const secret =
    await test.step('enroll TOTP; a wrong enrollment code grants nothing', async () => {
      await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
      await page.getByLabel(/current password/i).fill(E2E_PASSWORD)
      await submitUnthrottled(page, /set up two-factor/i, '/api/auth/two-factor/enable')
      const secretText = await page.getByTestId('totp-secret').textContent()
      const found = /([A-Z2-7]{16,})/i.exec(secretText ?? '')?.[1]
      if (found === undefined) {
        throw new Error(`no TOTP secret shown (got: ${secretText ?? 'nothing'})`)
      }
      // Rejected as a bad code (401), not merely throttled.
      const rejected = await submitUnthrottled(
        page,
        /verify two-factor code/i,
        '/api/step-up',
        () => wrongTotp(found)
      )
      expect(rejected).toBe(401)
      await expect(page.getByText(/that code did not verify/i)).toBeVisible({ timeout: 30_000 })
      await expectWithheld(page)

      const accepted = await submitUnthrottled(
        page,
        /verify two-factor code/i,
        '/api/step-up',
        () => totp(found)
      )
      expect(accepted).toBe(200)
      await expect(page.getByRole('status')).toContainText(/two-factor authentication is on/i, {
        timeout: 30_000,
      })
      return found
    })

  await test.step('sign out; a password-only sign-in now stops at the second factor', async () => {
    const out = await pageFetch(page, 'DELETE', '/api/auth-link/session')
    expect(out.status).toBe(200)
    await page.context().clearCookies()
    await gotoOwn(page, '/sign-in')
    const signIn = await pageFetch(page, 'POST', '/api/auth/sign-in/email', {
      email,
      password: E2E_PASSWORD,
    })
    expect(signIn.status).toBe(200)
    expect((signIn.body as { twoFactorRedirect?: unknown } | null)?.twoFactorRedirect).toBe(true)
    // 2FA-pending: no session at all yet, so no role either.
    expect((await readSession(page)).status).toBe(401)
  })

  await test.step('a wrong TOTP code does not grant the role', async () => {
    const wrong = await verifyTotp(page, () => wrongTotp(secret))
    // Rejected as a bad code (401), not merely throttled.
    expect(wrong.status, JSON.stringify(wrong.body)).toBe(401)
    expect((await readSession(page)).status).toBe(401)
    await gotoSettled(page, '/auditor-only')
    await expect(page.getByTestId('auditor-granted')).toHaveCount(0)
  })

  await test.step('password + correct TOTP grants the role and opens the gated page', async () => {
    await gotoOwn(page, '/sign-in')
    const verified = await verifyTotp(page, () => totp(secret))
    expect(verified.status, JSON.stringify(verified.body)).toBe(200)
    await expectGranted(page)
    const session = await readSession(page)
    expect(String(session.body?.user?.id)).toBe(userId)
    await gotoOwn(page, '/auditor-only')
    await expect(page.getByTestId('auditor-granted')).toContainText(email, { timeout: 30_000 })
  })
})
