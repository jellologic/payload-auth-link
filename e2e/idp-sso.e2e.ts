import { expect, test } from '@playwright/test'
import {
  approveAtMockIdp,
  asAdmin,
  payloadUsersByEmail,
  readSession,
  signUpInPage,
  startAuthJsSignIn,
  uniqueEmail,
  verifyDomainAsAdmin,
} from './idp-helpers.js'
import { gotoOwn, pageFetch } from './helpers.js'

/**
 * Enterprise SSO domain enforcement (CAP-15) on the external-IdP
 * variant: Auth.js is registered as the SSO provider
 * (`organizations.ssoProviders: ['authjs']`) with an OIDC connection to
 * the local mock IdP (`mock-sso`). A tenant IdP can assert a verified
 * email for anyone, so the trust boundary is the organization's
 * verified domain — which only Payload role managers may set.
 */

test('SSO admits a role-manager-verified domain and refuses every other', async ({
  page,
  browser,
  baseURL,
}) => {
  const domain = `corp-${Date.now()}.test`

  await test.step('before any organization verifies it, the domain is refused', async () => {
    const early = uniqueEmail('early', domain)
    await gotoOwn(page, '/sign-in')
    await startAuthJsSignIn(page, 'mock-sso')
    await approveAtMockIdp(page, early)
    await gotoOwn(page, '/sign-in')
    expect((await readSession(page)).status).toBe(401)
    await page.context().clearCookies()
  })

  await test.step('a non-role-manager cannot verify a domain', async () => {
    // Any signed-in Better Auth user (not an SSO provider) — a member,
    // not a role manager.
    await gotoOwn(page, '/sign-in')
    await signUpInPage(page, uniqueEmail('member'))
    const attempt = await pageFetch(page, 'POST', '/api/organizations', {
      name: 'Self-verified',
      slug: `self-${Date.now()}`,
      verifiedDomains: [{ domain }],
    })
    // Members may create organizations, but field access drops the
    // verified domains they tried to set. (On Payload v4 a create by a
    // provider-session user is refused outright — the known `createdBy`
    // gap in e2e/README.md — which verifies nothing either.)
    if (attempt.status === 201) {
      const created = attempt.body as { doc?: { verifiedDomains?: unknown[] } } | null
      expect(created?.doc?.verifiedDomains ?? []).toEqual([])
    } else {
      expect(attempt.status, JSON.stringify(attempt.body)).toBeGreaterThanOrEqual(400)
    }
    await pageFetch(page, 'DELETE', '/api/auth-link/session')
    await page.context().clearCookies()
  })

  await verifyDomainAsAdmin(browser, baseURL, domain)

  await test.step('an SSO sign-in on the verified domain links', async () => {
    const email = uniqueEmail('alice', domain)
    await gotoOwn(page, '/sign-in')
    await startAuthJsSignIn(page, 'mock-sso')
    await approveAtMockIdp(page, email)
    await expect(page).toHaveURL(/\/account/)
    await expect(page.getByTestId('account-email')).toContainText(email, { timeout: 30_000 })
    const session = await readSession(page)
    expect(session.status).toBe(200)
    expect(session.user?.email).toBe(email)
    await pageFetch(page, 'DELETE', '/api/auth-link/session')
    await page.context().clearCookies()
  })

  await test.step('foreign and subdomain assertions are refused, never provisioned', async () => {
    for (const email of [
      uniqueEmail('mallory', 'other.test'),
      uniqueEmail('eve', `mail.${domain}`),
    ]) {
      await gotoOwn(page, '/sign-in')
      await startAuthJsSignIn(page, 'mock-sso')
      await approveAtMockIdp(page, email)
      await gotoOwn(page, '/sign-in')
      expect((await readSession(page)).status, email).toBe(401)
      const users = await asAdmin(browser, baseURL, (adminPage) =>
        payloadUsersByEmail(adminPage, email)
      )
      expect(users, email).toHaveLength(0)
      await page.context().clearCookies()
    }
  })
})
