import {
  expect,
  test,
  type APIRequestContext,
  type APIResponse,
  type Browser,
  type BrowserContext,
  type Page,
} from '@playwright/test'
import { adminContext } from './admin-session.js'
import { gotoSettled, pageFetch, signUpVerified } from './helpers.js'

/**
 * Payload-owned organizations (CAP-11), wired in both examples with
 * `authLink({ organizations: { enabled: true } })`: create through the
 * plugin endpoint, invite by email, the invitee signs up and accepts,
 * reads are scoped to members, membership writes stay inside the
 * caller's organization and rank, the last owner cannot leave, and the
 * owner deletes the organization (cascading its memberships).
 *
 * Pure API over each user's own browser context: the behaviour is
 * HTTP-visible on every example and adapter. Plugin endpoints carry
 * the CSRF header; collection writes carry a same-origin `Origin`
 * (what the admin UI and any browser fetch send).
 *
 * Known product gap on Payload v4 (the TanStack Start example): v4 adds
 * `createdBy`/`updatedBy` relationships to every collection, filled
 * from `req.user`, and the plugin strategy projects `req.user.id` as a
 * string — so on numeric-id adapters (SQLite, Postgres) any create by
 * a provider-session user, the plugin's organization endpoint
 * included, fails validation (400). The endpoint test is `fixme` on
 * v4; the lifecycle test seeds its organizations as the seeded admin
 * there (a local Payload user, numeric id) and covers everything
 * after creation on both lines. Re-enable once the projection keeps
 * the adapter's id type.
 */

const payloadV4 = (): boolean => test.info().config.metadata['payloadMajor'] === 4

type Member = {
  readonly context: BrowserContext
  readonly api: APIRequestContext
  readonly userId: string
  readonly email: string
}

let counter = 0

function uniqueEmail(tag: string): string {
  counter += 1
  return `e2e-org-${tag}-${test.info().project.name}-${Date.now()}-${counter}@example.com`
}

function origin(): string {
  const baseURL = test.info().project.use.baseURL
  if (baseURL === undefined) {
    throw new Error('organizations.spec needs a configured baseURL')
  }
  return baseURL
}

async function newMember(browser: Browser, email: string): Promise<Member> {
  const context = await browser.newContext({ baseURL: origin() })
  const { userId } = await signUpVerified(context.request, email)
  return { context, api: context.request, userId, email }
}

const csrf = { 'x-auth-link-csrf': '1' }

async function json<T>(response: APIResponse): Promise<T> {
  return (await response.json()) as T
}

type OrgList = {
  organizations: Array<{ id: string; name: string | null; slug: string | null; role: string }>
  invitations: Array<{ id: string; organizationId: string; role: string }>
}

type MembershipDocs = {
  docs: Array<{
    id: number | string
    user: number | string | null
    organization: number | string
    role: string
  }>
}

function slugFor(name: string): string {
  return `${name.toLowerCase()}-${test.info().project.name}-${Date.now()}`
}

/** Create through the plugin endpoint: the creator becomes the owner. */
async function createOrg(member: Member, name: string): Promise<string> {
  const slug = slugFor(name)
  const created = await member.api.post('/api/auth-link/organizations', {
    headers: csrf,
    data: { name, slug },
  })
  expect(created.status(), await created.text()).toBe(201)
  const body = await json<{ organization: { id: string; slug: string } }>(created)
  expect(body.organization.slug).toBe(slug)
  return body.organization.id
}

/** Relationship ids keep the adapter's type: numbers on SQL, strings on Mongo. */
function relationId(id: string): string | number {
  return /^\d+$/.test(id) ? Number(id) : id
}

/**
 * Payload v4 path (see the header): the seeded admin creates the
 * organization over REST (becoming its owner), hands ownership to
 * `member`, then leaves — the same end state as {@link createOrg}.
 */
async function seedOrg(adminPage: Page, member: Member, name: string): Promise<string> {
  const created = await pageFetch(adminPage, 'POST', '/api/organizations', {
    name,
    slug: slugFor(name),
  })
  expect(created.status, JSON.stringify(created.body)).toBe(201)
  const orgId = String((created.body as { doc: { id: string | number } }).doc.id)
  const owner = await pageFetch(adminPage, 'POST', '/api/memberships', {
    organization: relationId(orgId),
    user: relationId(member.userId),
    role: 'owner',
    status: 'active',
  })
  expect(owner.status, JSON.stringify(owner.body)).toBe(201)
  const rows = await pageFetch(
    adminPage,
    'GET',
    `/api/memberships?depth=0&where[organization][equals]=${orgId}`
  )
  for (const row of (rows.body as MembershipDocs).docs) {
    if (String(row.user) !== member.userId) {
      const left = await pageFetch(adminPage, 'DELETE', `/api/memberships/${String(row.id)}`)
      expect(left.status, JSON.stringify(left.body)).toBe(200)
    }
  }
  return orgId
}

async function ownMembershipId(member: Member, organizationId: string): Promise<string> {
  const list = await member.api.get(
    `/api/memberships?depth=0&where[user][equals]=${member.userId}&where[organization][equals]=${organizationId}`
  )
  expect(list.ok()).toBe(true)
  const row = (await json<MembershipDocs>(list)).docs[0]
  if (row === undefined) {
    throw new Error(`no membership for user ${member.userId} in ${organizationId}`)
  }
  return String(row.id)
}

test('the plugin endpoint creates an organization owned by its creator (CSRF-guarded)', async ({
  browser,
}) => {
  test.fixme(
    payloadV4(),
    'Payload v4: provider-session creates fail createdBy validation (string req.user.id)'
  )
  const creator = await newMember(browser, uniqueEmail('creator'))
  try {
    const orgId = await createOrg(creator, 'Acme')
    const mine = await json<OrgList>(await creator.api.get('/api/auth-link/organizations'))
    expect(mine.organizations).toEqual([
      expect.objectContaining({ id: orgId, name: 'Acme', role: 'owner' }),
    ])
    // Creating an organization is a state change: no CSRF proof, no org.
    const noCsrf = await creator.api.post('/api/auth-link/organizations', {
      data: { name: 'NoCsrf', slug: slugFor('nocsrf') },
    })
    expect(noCsrf.status()).toBe(403)
    const after = await json<OrgList>(await creator.api.get('/api/auth-link/organizations'))
    expect(after.organizations).toHaveLength(1)
  } finally {
    await creator.context.close()
  }
})

test('organization lifecycle: invite, accept, scoped reads, governance, delete', async ({
  browser,
}) => {
  const owner = await newMember(browser, uniqueEmail('owner'))
  const outsider = await newMember(browser, uniqueEmail('outsider'))
  const admin = await adminContext(browser, origin())
  const contexts: BrowserContext[] = [owner.context, outsider.context, admin]
  try {
    const adminPage = await admin.newPage()
    await gotoSettled(adminPage, '/admin')
    const newOrg = (member: Member, name: string): Promise<string> =>
      payloadV4() ? seedOrg(adminPage, member, name) : createOrg(member, name)

    const orgId = await newOrg(owner, 'Acme')
    const mine = await json<OrgList>(await owner.api.get('/api/auth-link/organizations'))
    expect(mine.organizations).toEqual([expect.objectContaining({ id: orgId, role: 'owner' })])

    // Invite an address that has no Payload user yet: the invitation
    // waits (status `invited`); a duplicate invite is refused.
    const inviteeEmail = uniqueEmail('invitee')
    const invited = await owner.api.post('/api/auth-link/organizations/invite', {
      headers: csrf,
      data: { organizationId: orgId, email: inviteeEmail },
    })
    expect(invited.status(), await invited.text()).toBe(201)
    const invitation = await json<{ invitation: { id: string; status: string; role: string } }>(
      invited
    )
    expect(invitation.invitation).toMatchObject({ status: 'invited', role: 'member' })
    const duplicate = await owner.api.post('/api/auth-link/organizations/invite', {
      headers: csrf,
      data: { organizationId: orgId, email: inviteeEmail },
    })
    expect(duplicate.status()).toBe(409)

    // A non-member cannot invite into someone else's organization.
    const foreignInvite = await outsider.api.post('/api/auth-link/organizations/invite', {
      headers: csrf,
      data: { organizationId: orgId, email: uniqueEmail('stranger') },
    })
    expect(foreignInvite.status()).toBe(403)

    // The invitee signs up with the invited address and sees the
    // pending invitation; only they can accept it.
    const invitee = await newMember(browser, inviteeEmail)
    contexts.push(invitee.context)
    const pending = await json<OrgList>(await invitee.api.get('/api/auth-link/organizations'))
    expect(pending.organizations).toEqual([])
    expect(pending.invitations).toEqual([
      expect.objectContaining({ id: invitation.invitation.id, organizationId: orgId }),
    ])
    const stolen = await outsider.api.post('/api/auth-link/organizations/accept', {
      headers: csrf,
      data: { invitationId: invitation.invitation.id },
    })
    expect(stolen.status()).toBe(403)
    const accepted = await invitee.api.post('/api/auth-link/organizations/accept', {
      headers: csrf,
      data: { invitationId: invitation.invitation.id },
    })
    expect(accepted.status(), await accepted.text()).toBe(200)
    const joined = await json<OrgList>(await invitee.api.get('/api/auth-link/organizations'))
    expect(joined.organizations).toEqual([
      expect.objectContaining({ id: orgId, name: 'Acme', role: 'member' }),
    ])
    expect(joined.invitations).toEqual([])

    // Member read scoping: the invitee reads its own organization and
    // its memberships, never another tenant's.
    const otherOrgId = await newOrg(outsider, 'Other')
    const orgs = await json<{ docs: Array<{ id: number | string }> }>(
      await invitee.api.get('/api/organizations?depth=0')
    )
    expect(orgs.docs.map((doc) => String(doc.id))).toEqual([orgId])
    const foreignOrg = await invitee.api.get(`/api/organizations/${otherOrgId}`)
    expect(foreignOrg.status()).toBe(404)
    const visible = await json<MembershipDocs>(
      await invitee.api.get('/api/memberships?depth=0&limit=100')
    )
    expect(visible.docs.length).toBe(2)
    for (const row of visible.docs) {
      expect(String(row.organization)).toBe(orgId)
    }

    // A member cannot rewrite another organization's membership (nor
    // the owner's row in their own organization): 403, row unchanged.
    const outsiderRow = await ownMembershipId(outsider, otherOrgId)
    const crossTenant = await invitee.api.patch(`/api/memberships/${outsiderRow}`, {
      headers: { origin: origin() },
      data: { role: 'member' },
    })
    expect(crossTenant.status()).toBe(403)
    const ownerRow = await ownMembershipId(owner, orgId)
    const demoteOwner = await invitee.api.patch(`/api/memberships/${ownerRow}`, {
      headers: { origin: origin() },
      data: { role: 'member' },
    })
    expect(demoteOwner.status()).toBe(403)
    const stillOwner = await json<MembershipDocs>(
      await outsider.api.get(`/api/memberships?depth=0&where[id][equals]=${outsiderRow}`)
    )
    expect(stillOwner.docs[0]?.role).toBe('owner')

    // The last owner cannot leave (or be demoted): 409.
    const leave = await owner.api.delete(`/api/memberships/${ownerRow}`, {
      headers: { origin: origin() },
    })
    expect(leave.status(), await leave.text()).toBe(409)
    const demoteSelf = await owner.api.patch(`/api/memberships/${ownerRow}`, {
      headers: { origin: origin() },
      data: { role: 'member' },
    })
    expect(demoteSelf.status(), await demoteSelf.text()).toBe(409)

    // Deleting an organization is owner-only...
    const memberDelete = await invitee.api.delete(`/api/organizations/${orgId}`, {
      headers: { origin: origin() },
    })
    expect(memberDelete.status()).toBe(403)
    // ...and the owner's delete cascades the memberships.
    const deleted = await owner.api.delete(`/api/organizations/${orgId}`, {
      headers: { origin: origin() },
    })
    expect(deleted.status(), await deleted.text()).toBe(200)
    const after = await json<OrgList>(await invitee.api.get('/api/auth-link/organizations'))
    expect(after.organizations).toEqual([])
    const orphaned = await json<MembershipDocs>(await invitee.api.get('/api/memberships?depth=0'))
    expect(orphaned.docs).toEqual([])

    // The other tenant is untouched.
    const untouched = await json<OrgList>(await outsider.api.get('/api/auth-link/organizations'))
    expect(untouched.organizations).toEqual([
      expect.objectContaining({ id: otherOrgId, role: 'owner' }),
    ])
  } finally {
    await Promise.all(contexts.map((context) => context.close()))
  }
})
