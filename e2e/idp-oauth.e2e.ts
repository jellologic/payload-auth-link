import { expect, test } from '@playwright/test'
import {
  approveAtMockIdp,
  asAdmin,
  mintOneTapToken,
  payloadUsersByEmail,
  postAuthJsOneTap,
  readSession,
  startBetterAuthOAuth,
  uniqueEmail,
  verifyDomainAsAdmin,
} from './idp-helpers.js'
import { gotoOwn, pageFetch } from './helpers.js'

/**
 * Social OAuth (CAP-3) and Google One Tap (CAP-4) against the local
 * mock OIDC provider (`mock-idp.ts`), on the external-IdP variant.
 *
 * - Better Auth `genericOAuth` runs the whole browser round trip:
 *   app → IdP consent form → app callback. The plugin links only an
 *   IdP-asserted verified email; an unverified assertion leaves a
 *   provider session the plugin refuses, and no Payload user.
 * - Better Auth `oneTap` verifies against Google's JWKS, which Better
 *   Auth hardcodes (no override): a token signed by any other key —
 *   every token a test can mint — is refused. That refusal is the
 *   whole observable surface without Google itself.
 * - The Auth.js One Tap recipe (`createGoogleOneTapAuthorize`) takes a
 *   `jwksUrl`, so the variant points it at the mock's Google-shaped
 *   JWKS and the full sign-in runs: a verified token links; a wrong
 *   audience, an unverified email, and a tampered signature do not.
 *   Auth.js is the variant's SSO provider, so the email sits on an
 *   organization-verified domain (see `idp-sso.e2e.ts`).
 * Google's browser widget itself is Google's script and never runs.
 */

test('social OAuth: an IdP-verified email links and provisions a Payload user', async ({
  page,
}) => {
  const email = uniqueEmail('oauth')
  await gotoOwn(page, '/sign-in')
  await startBetterAuthOAuth(page)
  await approveAtMockIdp(page, email)
  await expect(page).toHaveURL(/\/account/)
  await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })

  const session = await readSession(page)
  expect(session.status).toBe(200)
  expect(session.user?.email).toBe(email)
  expect(session.user?.roles).toEqual(['user'])
})

test('social OAuth: an unverified IdP email gets no Payload session or user', async ({
  page,
  browser,
  baseURL,
}) => {
  const email = uniqueEmail('oauth-unverified')
  await gotoOwn(page, '/sign-in')
  await startBetterAuthOAuth(page)
  await approveAtMockIdp(page, email, { verified: false })

  // Better Auth holds a provider session; the plugin refuses to link it.
  await gotoOwn(page, '/sign-in')
  expect((await readSession(page)).status).toBe(401)
  const users = await asAdmin(browser, baseURL, (adminPage) =>
    payloadUsersByEmail(adminPage, email)
  )
  expect(users).toHaveLength(0)
})

test('One Tap (Better Auth): a token not signed by Google is refused', async ({ page }) => {
  const email = uniqueEmail('onetap-ba')
  await gotoOwn(page, '/sign-in')
  const forged = await mintOneTapToken(page.request, { email })
  const result = await pageFetch(page, 'POST', '/api/auth/one-tap/callback', { idToken: forged })
  expect(result.status, JSON.stringify(result.body)).toBe(400)
  expect((await readSession(page)).status).toBe(401)
})

test('One Tap (Auth.js recipe): a verified Google token links; bad tokens do not', async ({
  page,
  browser,
  baseURL,
}) => {
  const domain = `onetap-${Date.now()}.test`
  await verifyDomainAsAdmin(browser, baseURL, domain)
  await gotoOwn(page, '/sign-in')

  await test.step('wrong audience, unverified email, tampered signature: refused', async () => {
    const wrongAudience = await mintOneTapToken(page.request, {
      email: uniqueEmail('aud', domain),
      aud: 'someone-elses-client',
    })
    expect(await postAuthJsOneTap(page, wrongAudience)).toBe(false)
    const unverified = await mintOneTapToken(page.request, {
      email: uniqueEmail('unverified', domain),
      verified: false,
    })
    expect(await postAuthJsOneTap(page, unverified)).toBe(false)
    // Same header and signature, different claims: the signature no
    // longer covers the payload.
    const genuine = await mintOneTapToken(page.request, { email: uniqueEmail('real', domain) })
    const swapped = await mintOneTapToken(page.request, { email: uniqueEmail('evil', domain) })
    const [header, , signature] = genuine.split('.')
    const [, evilPayload] = swapped.split('.')
    expect(await postAuthJsOneTap(page, `${header}.${evilPayload}.${signature}`)).toBe(false)
    expect((await readSession(page)).status).toBe(401)
  })

  await test.step('a verified token signs in and links a Payload user', async () => {
    const email = uniqueEmail('onetap', domain)
    const credential = await mintOneTapToken(page.request, { email })
    expect(await postAuthJsOneTap(page, credential)).toBe(true)
    const session = await readSession(page)
    expect(session.status).toBe(200)
    expect(session.user?.email).toBe(email)
  })
})
