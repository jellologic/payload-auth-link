import { randomInt, randomUUID } from 'node:crypto'
import { expect, type APIRequestContext, type Browser, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { E2E_PASSWORD, gotoSettled, pageFetch } from './helpers.js'

/**
 * Shared helpers for the external-IdP variant specs (`idp-*.e2e.ts`,
 * run by `playwright.idp.config.ts` and its TanStack twin against the
 * local mock OIDC provider in `mock-idp.ts`).
 */
export const MOCK_IDP_PORT = 3190
export const MOCK_IDP_ORIGIN = `http://localhost:${String(MOCK_IDP_PORT)}`

/** The variant's One Tap client id (examples' `lib/e2e-idp.ts`). */
export const ONE_TAP_CLIENT_ID = 'e2e-google-one-tap-client'

/** Unique per call, across engines and repeats (one shared database). */
export function uniqueEmail(prefix: string, domain = 'idp-e2e.test'): string {
  return `${prefix}-${randomUUID().slice(0, 12)}@${domain}`
}

/** A unique E.164 number in the reserved +1 555 01xx fiction range shape. */
export function uniquePhone(): string {
  return `+1555${String(randomInt(1_000_000, 9_999_999))}`
}

export type SessionUser = {
  id: string | number
  email: string
  roles: string[]
}

/** The plugin session as the page's own cookies present it. */
export async function readSession(
  page: Page
): Promise<{ status: number; user: SessionUser | null }> {
  const result = await pageFetch(page, 'GET', '/api/auth-link/session')
  const body = result.body as { user?: SessionUser | null } | null
  return { status: result.status, user: result.status === 200 ? (body?.user ?? null) : null }
}

/**
 * Sign a fresh Better Auth email+password user up FROM THE PAGE (so
 * the request carries the app `Origin`, which Better Auth requires once
 * the browser already holds a session — e.g. a second multi-session
 * account), stamp them verified via the example's dev-only route, and
 * return the linked Payload user id.
 */
export async function signUpInPage(page: Page, email: string): Promise<string> {
  const signup = await pageFetch(page, 'POST', '/api/auth/sign-up/email', {
    name: email,
    email,
    password: E2E_PASSWORD,
  })
  expect(signup.status, `sign-up ${email}: ${JSON.stringify(signup.body)}`).toBe(200)
  const stamped = await pageFetch(page, 'POST', '/api/dev-auto-verify', { email })
  expect(stamped.status).toBe(200)
  const session = await readSession(page)
  expect(session.user?.email).toBe(email)
  return String(session.user?.id)
}

/** Start Better Auth social sign-in and follow the browser to the IdP. */
export async function startBetterAuthOAuth(page: Page, callbackPath = '/account'): Promise<void> {
  const start = await pageFetch(page, 'POST', '/api/auth/sign-in/social', {
    provider: 'mock-idp',
    callbackURL: callbackPath,
  })
  expect(start.status, JSON.stringify(start.body)).toBe(200)
  const authorizeUrl = (start.body as { url?: unknown } | null)?.url
  if (typeof authorizeUrl !== 'string') {
    throw new Error(`sign-in/social returned no IdP URL: ${JSON.stringify(start.body)}`)
  }
  await page.goto(authorizeUrl)
}

/**
 * Complete the mock IdP's consent form the browser was redirected to,
 * as `email` (with the IdP asserting `email_verified` or not), and wait
 * for the redirect back to the app.
 */
export async function approveAtMockIdp(
  page: Page,
  email: string,
  options: { verified?: boolean } = {}
): Promise<void> {
  await expect(page).toHaveURL(new RegExp(`^${MOCK_IDP_ORIGIN}/authorize`))
  await page.getByLabel('IdP email').fill(email)
  if (options.verified === false) {
    await page.getByLabel('Email verified').uncheck()
  }
  await Promise.all([
    page.waitForURL((url) => !url.toString().startsWith(MOCK_IDP_ORIGIN), { timeout: 60_000 }),
    page.getByRole('button', { name: 'Approve' }).click(),
  ])
}

/**
 * Start an Auth.js sign-in for `providerId` the way its sign-in page
 * does: a CSRF-token form POST to `/api/authjs/signin/:id`, submitted
 * by the page so the browser follows the redirect to the IdP.
 */
export async function startAuthJsSignIn(
  page: Page,
  providerId: string,
  callbackPath = '/account'
): Promise<void> {
  await page.evaluate(
    async ({ providerId, callbackPath }) => {
      const csrf = (await (await fetch('/api/authjs/csrf')).json()) as { csrfToken: string }
      const form = document.createElement('form')
      form.method = 'POST'
      form.action = `/api/authjs/signin/${providerId}`
      for (const [name, value] of [
        ['csrfToken', csrf.csrfToken],
        ['callbackUrl', `${window.location.origin}${callbackPath}`],
      ] as const) {
        const input = document.createElement('input')
        input.type = 'hidden'
        input.name = name
        input.value = value
        form.append(input)
      }
      document.body.append(form)
      form.submit()
    },
    { providerId, callbackPath }
  )
}

/** A Google-shaped One Tap ID token minted by the mock IdP's key. */
export async function mintOneTapToken(
  request: APIRequestContext,
  claims: { email: string; aud?: string; verified?: boolean }
): Promise<string> {
  const response = await request.post(`${MOCK_IDP_ORIGIN}/google/id-token`, {
    form: {
      email: claims.email,
      aud: claims.aud ?? ONE_TAP_CLIENT_ID,
      email_verified: claims.verified === false ? 'false' : 'true',
    },
  })
  expect(response.ok()).toBe(true)
  const body = (await response.json()) as { credential: string }
  return body.credential
}

/**
 * Post a One Tap credential to the Auth.js recipe's Credentials
 * callback (what the page's One Tap handler does with Google's token)
 * and report whether Auth.js signed the browser in.
 */
export async function postAuthJsOneTap(page: Page, credential: string): Promise<boolean> {
  const csrf = await page.request.get('/api/authjs/csrf')
  const { csrfToken } = (await csrf.json()) as { csrfToken: string }
  const response = await page.request.post('/api/authjs/callback/google-one-tap', {
    form: { csrfToken, credential, callbackUrl: '/account' },
    maxRedirects: 0,
  })
  const location = response.headers()['location'] ?? ''
  return response.status() === 302 && !location.includes('error=')
}

/**
 * The newest phone OTP the example's dev SMS outbox captured for
 * `phone` at or after `since` (epoch ms; same host clock as the server).
 */
export async function readSmsCode(
  request: APIRequestContext,
  phone: string,
  since: number
): Promise<string> {
  let code = ''
  await expect(async () => {
    const response = await request.get(`/api/dev-sms?phoneNumber=${encodeURIComponent(phone)}`)
    expect(response.ok()).toBe(true)
    const body = (await response.json()) as { messages: { code: string; at: number }[] }
    const latest = body.messages.find((message) => message.at >= since)?.code
    expect(latest, `no SMS captured for ${phone}`).toBeDefined()
    code = latest ?? ''
  }).toPass({ timeout: 15_000 })
  return code
}

/** Run `work` as the shared seeded admin (one login per run). */
export async function asAdmin<T>(
  browser: Browser,
  baseURL: string | undefined,
  work: (adminPage: Page) => Promise<T>
): Promise<T> {
  const admin = await adminContext(browser, baseURL)
  try {
    const adminPage = await admin.newPage()
    await gotoSettled(adminPage, '/admin')
    return await work(adminPage)
  } finally {
    await admin.close()
  }
}

export type AdminUserRow = {
  id: string | number
  email: string
  roles?: string[]
  phone?: string | null
}

/** Payload users with this email, as the admin sees them. */
export async function payloadUsersByEmail(adminPage: Page, email: string): Promise<AdminUserRow[]> {
  const found = await pageFetch(
    adminPage,
    'GET',
    `/api/users?depth=0&where[email][equals]=${encodeURIComponent(email)}`
  )
  expect(found.status, JSON.stringify(found.body)).toBe(200)
  return (found.body as { docs: AdminUserRow[] }).docs
}

/**
 * As a Payload role manager, create an organization that verifies
 * `domain` (CAP-15). Auth.js is the variant's SSO provider, so its
 * sessions then link on that domain — and only on verified domains.
 */
export async function verifyDomainAsAdmin(
  browser: Browser,
  baseURL: string | undefined,
  domain: string
): Promise<void> {
  await asAdmin(browser, baseURL, async (adminPage) => {
    const created = await pageFetch(adminPage, 'POST', '/api/organizations', {
      name: `SSO ${domain}`,
      slug: `sso-${randomUUID().slice(0, 8)}`,
      verifiedDomains: [{ domain }],
    })
    expect(created.status, JSON.stringify(created.body)).toBe(201)
  })
}

/** A six-digit code guaranteed to differ from `code`. */
export function wrongCode(code: string): string {
  const first = code.charAt(0) === '9' ? '0' : String(Number(code.charAt(0)) + 1)
  return `${first}${code.slice(1)}`
}
