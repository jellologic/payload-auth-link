import { expect, test } from '@playwright/test'
import { asAdmin, readSession, uniqueEmail } from './idp-helpers.js'
import { gotoOwn, pageFetch, setRolesAsAdmin, signUpVerified } from './helpers.js'

/**
 * Storage-edge options on the external-IdP variant (own database):
 *
 * - `roleValues: { editor: 'contentEditor' }` (issue #56): the users
 *   `roles` select stores — and Payload's REST/admin surface reads and
 *   writes — the mapped value `contentEditor` (its option is labelled
 *   `editor`), so a payload-auth-era database keeps its values. The
 *   plugin translates at that edge: the session and every access
 *   function see the canonical `editor`, which is what the `memos`
 *   create access checks.
 * - `reqUser: 'document'` (issue #57): `req.user` is the full user
 *   document, so the `memos` read access — which checks the host
 *   `department` field the session projection never carries — works.
 *   Under the default projection the same access would deny everyone.
 */
test('a role stored as its mapped value reads canonically and gates access', async ({
  page,
  browser,
  baseURL,
}) => {
  const editor = uniqueEmail('editor')
  await gotoOwn(page, '/sign-in')
  const { userId } = await signUpVerified(page.request, editor)

  await test.step('without the role, creating a memo is forbidden', async () => {
    const denied = await pageFetch(page, 'POST', '/api/memos', { title: 'not yet' })
    expect(denied.status).toBe(403)
  })

  await test.step('the admin grants the role in its stored form', async () => {
    await asAdmin(browser, baseURL, async (adminPage) => {
      await setRolesAsAdmin(adminPage, userId, ['user', 'contentEditor'])
      const read = await pageFetch(adminPage, 'GET', `/api/users/${userId}?depth=0`)
      expect((read.body as { roles: string[] }).roles.sort()).toEqual(['contentEditor', 'user'])
    })
  })

  await test.step('the session reads canonically and the role opens access', async () => {
    const session = await readSession(page)
    expect(session.user?.roles.sort()).toEqual(['editor', 'user'])
    expect(session.user?.roles).not.toContain('contentEditor')
    const created = await pageFetch(page, 'POST', '/api/memos', { title: 'editor memo' })
    expect(created.status, JSON.stringify(created.body)).toBe(201)
  })
})

test("reqUser 'document': an access function reading a host field works", async ({
  page,
  browser,
  baseURL,
}) => {
  const researcher = uniqueEmail('research')
  await gotoOwn(page, '/sign-in')
  const { userId } = await signUpVerified(page.request, researcher)

  await test.step('without the host field, reads are denied', async () => {
    const denied = await pageFetch(page, 'GET', '/api/memos?depth=0')
    expect(denied.status).toBe(403)
  })

  await asAdmin(browser, baseURL, async (adminPage) => {
    const patched = await pageFetch(adminPage, 'PATCH', `/api/users/${userId}`, {
      department: 'research',
    })
    expect(patched.status, JSON.stringify(patched.body)).toBe(200)
    const seeded = await pageFetch(adminPage, 'POST', '/api/memos', { title: 'research memo' })
    expect(seeded.status, JSON.stringify(seeded.body)).toBe(201)
  })

  await test.step('with department=research on the document, reads pass', async () => {
    const allowed = await pageFetch(page, 'GET', '/api/memos?depth=0')
    expect(allowed.status, JSON.stringify(allowed.body)).toBe(200)
    const titles = (allowed.body as { docs: { title: string }[] }).docs.map((doc) => doc.title)
    expect(titles).toContain('research memo')
    // The session projection stays the stable shape regardless.
    const session = await readSession(page)
    expect(String(session.user?.id)).toBe(userId)
  })
})
