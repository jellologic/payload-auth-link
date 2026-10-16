import { expect, test, type Page } from '@playwright/test'
import { adminContext } from './admin-session.js'
import { gotoSettled, pageFetch, setRolesAsAdmin, signUpVerified } from './helpers.js'

/**
 * Impersonation (CAP-8) through Better Auth's `admin()` plugin, wired in
 * both examples: a Better Auth operator impersonates a user, the plugin
 * resolves the operator as the session's `actor`, and while
 * impersonating the admin panel, role writes, and organization writes
 * are refused — even though the impersonated user is a Payload admin
 * and an organization owner, who could do all three on their own
 * session. Stopping impersonation restores the operator's session.
 *
 * The operator needs BA's provider-side `admin` role (granted by the
 * example's dev-only `/api/dev-provider-admin`) for BA's endpoints, and
 * the Payload `admin` role for the panel. Both users are demoted again
 * at the end so later specs on the shared server see plain users.
 *
 * Impersonate/stop and every state-changing call run as in-page
 * `fetch`: BA swaps and expires cookies on those responses, and the
 * browser (not WebKit's `page.request`) must apply the deletions.
 */

let counter = 0

function uniqueEmail(tag: string): string {
  counter += 1
  return `e2e-imp-${tag}-${test.info().project.name}-${Date.now()}-${counter}@example.com`
}

type SessionBody = {
  user: {
    id: string
    email: string
    roles: string[]
    actor?: { kind: string; userId?: string; providerUserId: string }
  }
}

async function session(page: Page): Promise<SessionBody['user']> {
  const result = await pageFetch(page, 'GET', '/api/auth-link/session')
  expect(result.status).toBe(200)
  return (result.body as SessionBody).user
}

/** The Payload admin dashboard rendered (its users-collection nav link). */
async function expectAdminPanel(page: Page): Promise<void> {
  await gotoSettled(page, '/admin')
  await expect(page).not.toHaveURL(/\/admin\/(login|unauthorized)/)
  await expect(page.locator('a[href*="/admin/collections/users"]').first()).toBeVisible({
    timeout: 30_000,
  })
}

test('an operator impersonates a user; privileged writes are refused until they stop', async ({
  browser,
  baseURL,
}) => {
  const admin = await adminContext(browser, baseURL)
  const operatorContext = await browser.newContext({ baseURL: baseURL ?? '' })
  const targetContext = await browser.newContext({ baseURL: baseURL ?? '' })
  const adminPage = await admin.newPage()
  await gotoSettled(adminPage, '/admin')

  const operatorEmail = uniqueEmail('operator')
  const targetEmail = uniqueEmail('target')
  const operator = await signUpVerified(operatorContext.request, operatorEmail)
  const target = await signUpVerified(targetContext.request, targetEmail)
  try {
    // Provider-side operator role (BA's admin endpoints) + Payload
    // admin on both: the target's own session could reach the panel
    // and write roles, so the refusals below are the impersonation
    // policy, not a missing grant.
    const granted = await operatorContext.request.post('/api/dev-provider-admin', {
      data: { email: operatorEmail },
    })
    expect(granted.ok()).toBe(true)
    await setRolesAsAdmin(adminPage, operator.userId, ['admin'])
    await setRolesAsAdmin(adminPage, target.userId, ['admin'])

    // The target co-owns an organization (so an invite on their own
    // session is allowed). The seeded admin creates it and adds the
    // target as an owner over REST (relationship ids keep the
    // adapter's type: numbers on SQL, strings on Mongo).
    const org = await pageFetch(adminPage, 'POST', '/api/organizations', {
      name: 'Target Org',
      slug: `imp-${test.info().project.name}-${Date.now()}`,
    })
    expect(org.status, JSON.stringify(org.body)).toBe(201)
    const orgId = String((org.body as { doc: { id: string | number } }).doc.id)
    const relationId = (id: string): string | number => (/^\d+$/.test(id) ? Number(id) : id)
    const owner = await pageFetch(adminPage, 'POST', '/api/memberships', {
      organization: relationId(orgId),
      user: relationId(target.userId),
      role: 'owner',
      status: 'active',
    })
    expect(owner.status, JSON.stringify(owner.body)).toBe(201)

    // Control: the operator's own session reaches the admin panel.
    const page = await operatorContext.newPage()
    await expectAdminPanel(page)
    const before = await session(page)
    expect(before.email).toBe(operatorEmail)
    expect(before.actor).toBeUndefined()

    // Impersonate. The session now resolves to the target, with the
    // operator recorded as the actor.
    const started = await pageFetch(page, 'POST', '/api/auth/admin/impersonate-user', {
      userId: target.providerUserId,
    })
    expect(started.status, JSON.stringify(started.body)).toBe(200)
    const impersonated = await session(page)
    expect(impersonated.email).toBe(targetEmail)
    expect(impersonated.roles).toContain('admin')
    expect(impersonated.actor).toMatchObject({ kind: 'payload-user', userId: operator.userId })

    // The admin panel is denied while impersonating.
    await gotoSettled(page, '/admin')
    await expect(page.locator('a[href*="/admin/collections/users"]')).toHaveCount(0)
    await expect(page).not.toHaveURL(/\/admin\/?$/)

    // Role writes are refused, and the stored roles do not move.
    const roleWrite = await pageFetch(page, 'PATCH', `/api/users/${target.userId}`, {
      roles: ['user'],
    })
    expect(roleWrite.status).toBe(403)
    const stored = await pageFetch(adminPage, 'GET', `/api/users/${target.userId}?depth=0`)
    expect((stored.body as { roles: string[] }).roles).toEqual(['admin'])

    // Organization management is refused too.
    const invite = await pageFetch(page, 'POST', '/api/auth-link/organizations/invite', {
      organizationId: orgId,
      email: uniqueEmail('invitee'),
    })
    expect(invite.status).toBe(403)
    const create = await pageFetch(page, 'POST', '/api/auth-link/organizations', {
      name: 'While Impersonating',
      slug: `imp-new-${test.info().project.name}-${Date.now()}`,
    })
    expect(create.status).toBe(403)
    const rename = await pageFetch(page, 'PATCH', `/api/organizations/${orgId}`, {
      name: 'Renamed While Impersonating',
    })
    expect(rename.status).toBe(403)

    // Stop: the operator's own session (and admin panel) comes back.
    const stopped = await pageFetch(page, 'POST', '/api/auth/admin/stop-impersonating', {})
    expect(stopped.status, JSON.stringify(stopped.body)).toBe(200)
    const restored = await session(page)
    expect(restored.email).toBe(operatorEmail)
    expect(restored.roles).toContain('admin')
    expect(restored.actor).toBeUndefined()
    await expectAdminPanel(page)

    // The same invite on the target's own session goes through: the
    // refusal above was the impersonation policy.
    const ownInvite = await targetContext.request.post('/api/auth-link/organizations/invite', {
      headers: { 'x-auth-link-csrf': '1' },
      data: { organizationId: orgId, email: uniqueEmail('invitee') },
    })
    expect(ownInvite.status()).toBe(201)
  } finally {
    await setRolesAsAdmin(adminPage, operator.userId, ['user'])
    await setRolesAsAdmin(adminPage, target.userId, ['user'])
    await Promise.all([admin.close(), operatorContext.close(), targetContext.close()])
  }
})
