import { expect, test, type Page } from '@playwright/test'
import { gotoOwn } from './helpers.js'

/**
 * Passwordless + guest flows (CAP-1/2/10) against the local dev
 * mailbox: no mail server anywhere. The mailbox API hands the test
 * the same link/code a real inbox would.
 */
let counter = 0

function uniqueEmail(tag: string): string {
  counter += 1
  return `pwless-${tag}-${Date.now()}-${counter}@example.com`
}

type DevMail = {
  kind: string
  email: string
  url?: string
  code?: string
}

async function mailbox(page: Page, email: string): Promise<DevMail[]> {
  const response = await page.request.get(`/api/dev-mailbox?email=${encodeURIComponent(email)}`)
  expect(response.ok()).toBe(true)
  const body = (await response.json()) as { messages: DevMail[] }
  return body.messages
}

async function latestMail(page: Page, email: string, kind: string): Promise<DevMail> {
  await expect
    .poll(async () => (await mailbox(page, email)).filter((entry) => entry.kind === kind).length, {
      timeout: 15_000,
    })
    .toBeGreaterThan(0)
  const entry = (await mailbox(page, email)).find((candidate) => candidate.kind === kind)
  if (entry === undefined) {
    throw new Error(`no ${kind} mail captured for ${email}`)
  }
  return entry
}

test.beforeEach(async ({ page }) => {
  await page.request.delete('/api/dev-mailbox')
})

test('Better Auth magic link signs in and provisions the Payload user', async ({ page }) => {
  const email = uniqueEmail('magic')
  await gotoOwn(page, '/sign-in/passwordless')
  await page.getByLabel(/^email$/i).fill(email)
  await page.getByRole('button', { name: /sign-in link/i }).click()
  const mail = await latestMail(page, email, 'magic-link')
  if (mail.url === undefined) {
    throw new Error('magic-link mail carried no URL')
  }
  await page.goto(mail.url)
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  const session = await page.request.get('/api/auth-link/session')
  expect(session.ok()).toBe(true)
  // Replay: the same link must not mint a second session. Replay over
  // HTTP rather than a browser navigation: the spent link's error
  // redirect lands on a signed-out page that bounces to sign-in, and
  // Firefox reports that collision as NS_BINDING_ABORTED on goto.
  // page.request shares the context cookie jar, so a wrongly minted
  // session cookie would still show up in the session check below.
  await page.context().clearCookies()
  await page.request.get(mail.url)
  const replayed = await page.request.get('/api/auth-link/session')
  expect(replayed.status()).toBe(401)
})

test('Better Auth email OTP verifies a code and signs in', async ({ page }) => {
  const email = uniqueEmail('otp')
  await gotoOwn(page, '/sign-in/passwordless')
  await page.getByLabel(/^email$/i).fill(email)
  await page.getByRole('button', { name: /sign-in code/i }).click()
  const mail = await latestMail(page, email, 'email-otp')
  if (mail.code === undefined) {
    throw new Error('email-otp mail carried no code')
  }
  await page.getByLabel(/sign-in code/i).fill(mail.code)
  await page.getByRole('button', { name: /verify code/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
})

test('guest session reports a principal, then upgrades by signing in', async ({ page }) => {
  await gotoOwn(page, '/sign-in/passwordless')
  await page.getByRole('button', { name: /continue as guest/i }).click()
  await expect(page.getByTestId('guest-id')).toBeVisible({ timeout: 30_000 })
  const session = await page.request.get('/api/auth-link/session')
  expect(session.ok()).toBe(true)
  const body = (await session.json()) as {
    user: unknown
    guest?: { id: string }
  }
  expect(body.user).toBeNull()
  expect(body.guest?.id).toBeTruthy()

  // Upgrade path: password sign-up replaces the guest with a user.
  const email = uniqueEmail('guest-upgrade')
  await gotoOwn(page, '/sign-in')
  await page.getByRole('button', { name: /need an account/i }).click()
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill('e2e-test-password-1')
  await page.getByRole('button', { name: /create account/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
  const upgraded = (await (await page.request.get('/api/auth-link/session')).json()) as {
    user: { email: string } | null
    guest?: unknown
  }
  expect(upgraded.user?.email).toBe(email)
  expect(upgraded.guest).toBeUndefined()
})

test('Auth.js magic link follows the mailbox URL into the account', async ({ page }) => {
  const email = uniqueEmail('authjs-magic')
  await gotoOwn(page, '/sign-in-authjs')
  await page.getByLabel(/email address/i).fill(email)
  await page.getByRole('button', { name: /sign-in link/i }).click()
  const mail = await latestMail(page, email, 'magic-link')
  if (mail.url === undefined) {
    throw new Error('authjs magic-link mail carried no URL')
  }
  await page.goto(mail.url)
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
})

test('Auth.js email OTP wrong codes throttle per identifier (429)', async ({ page }) => {
  const email = uniqueEmail('authjs-throttle')
  await gotoOwn(page, '/sign-in-authjs')
  await page.getByLabel(/email address/i).fill(email)
  await page.getByRole('button', { name: /sign-in link/i }).click()
  const mail = await latestMail(page, email, 'email-otp')
  if (mail.code === undefined) {
    throw new Error('authjs email mail carried no code')
  }
  const wrong = mail.code === '000000' ? '999999' : '000000'
  const callback = (token: string) =>
    page.request.get(
      `/api/authjs/callback/resend?token=${token}&email=${encodeURIComponent(email)}&callbackUrl=/account`,
      { maxRedirects: 0 }
    )
  for (let attempt = 0; attempt < 3; attempt += 1) {
    expect((await callback(wrong)).status()).not.toBe(429)
  }
  // The per-identifier cap (3) now throttles even the genuine code.
  expect((await callback(mail.code)).status()).toBe(429)
})

test('Auth.js email OTP verifies through the query-string callback', async ({ page }) => {
  const email = uniqueEmail('authjs-otp')
  await gotoOwn(page, '/sign-in-authjs')
  await page.getByLabel(/email address/i).fill(email)
  await page.getByRole('button', { name: /sign-in link/i }).click()
  const mail = await latestMail(page, email, 'email-otp')
  if (mail.code === undefined) {
    throw new Error('authjs email mail carried no code')
  }
  await page.getByLabel(/6-digit code/i).fill(mail.code)
  await page.getByRole('button', { name: /verify code/i }).click()
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
})
