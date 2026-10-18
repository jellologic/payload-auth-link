/**
 * Organizations integration (CAP-11, D1): real Payload (SQLite in
 * memory) with organizations enabled, driven through the plugin's
 * own endpoints. Proves create → owner membership, invite (existing
 * user joins immediately; unknown email waits for acceptance),
 * manager-only invites, CSRF on writes, and collection-level
 * membership scoping.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { parseRole, type Role } from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink, requireOrgRole } from '../index.js'
import type { PayloadRequest } from 'payload'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://orgs.test'
const SECRET = 'organizations-integration-secret!!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

const ownerCookie = () =>
  stub.issue({
    sessionId: `sess-owner-${Math.random()}`,
    providerUserId: 'stub-owner',
    email: 'owner@orgs.test',
    expiresAt: new Date(Date.now() + 3600_000),
  })
const memberCookie = () =>
  stub.issue({
    sessionId: `sess-member-${Math.random()}`,
    providerUserId: 'stub-member',
    email: 'member@orgs.test',
    expiresAt: new Date(Date.now() + 3600_000),
  })
const outsiderCookie = () =>
  stub.issue({
    sessionId: `sess-out-${Math.random()}`,
    providerUserId: 'stub-outsider',
    email: 'outsider@orgs.test',
    expiresAt: new Date(Date.now() + 3600_000),
  })

function call(
  method: string,
  path: string,
  opts: { cookie?: string; csrf?: boolean; body?: unknown } = {}
): Promise<Response> {
  const headers: Record<string, string> = {}
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.csrf === true) {
    headers['x-auth-link-csrf'] = '1'
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
}

type OrgsBody = {
  organizations: { id: string; slug: string | null; role: string }[]
  invitations: { id: string; organizationId: string; role: string }[]
}

let orgId = ''

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        organizations: { enabled: true },
      }),
    ],
  })
  payload = await getPayload({ config })
  // Both users exist as Payload users through the session endpoint.
  expect((await call('GET', '/auth-link/session', { cookie: ownerCookie() })).status).toBe(200)
  expect((await call('GET', '/auth-link/session', { cookie: memberCookie() })).status).toBe(200)
  expect((await call('GET', '/auth-link/session', { cookie: outsiderCookie() })).status).toBe(200)
}, 60_000)

describe('organization endpoints (CAP-11)', () => {
  it('requires a session and CSRF proof for writes', async () => {
    expect((await call('GET', '/auth-link/organizations')).status).toBe(401)
    expect(
      (
        await call('POST', '/auth-link/organizations', {
          cookie: ownerCookie(),
          body: { name: 'No CSRF', slug: 'no-csrf' },
        })
      ).status
    ).toBe(403)
  })

  it('creates an organization and seeds the creator as owner', async () => {
    const created = await call('POST', '/auth-link/organizations', {
      cookie: ownerCookie(),
      csrf: true,
      body: { name: 'Acme', slug: 'acme' },
    })
    expect(created.status).toBe(201)
    const body = (await created.json()) as { organization: { id: string } }
    orgId = body.organization.id

    const list = (await (
      await call('GET', '/auth-link/organizations', { cookie: ownerCookie() })
    ).json()) as OrgsBody
    expect(list.organizations).toEqual([
      expect.objectContaining({ id: orgId, slug: 'acme', role: 'owner' }),
    ])
    const outsiderList = (await (
      await call('GET', '/auth-link/organizations', { cookie: outsiderCookie() })
    ).json()) as OrgsBody
    expect(outsiderList.organizations).toEqual([])
  })

  it('invites an existing user straight to active membership', async () => {
    const invited = await call('POST', '/auth-link/organizations/invite', {
      cookie: ownerCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'member@orgs.test', role: 'member' },
    })
    expect(invited.status).toBe(201)
    const list = (await (
      await call('GET', '/auth-link/organizations', { cookie: memberCookie() })
    ).json()) as OrgsBody
    expect(list.organizations).toEqual([expect.objectContaining({ id: orgId, role: 'member' })])
  })

  it('refuses duplicate memberships and duplicate pending invitations', async () => {
    const duplicateMember = await call('POST', '/auth-link/organizations/invite', {
      cookie: ownerCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'member@orgs.test', role: 'admin' },
    })
    expect(duplicateMember.status).toBe(409)
    // The original role is unchanged (no competing row).
    const list = (await (
      await call('GET', '/auth-link/organizations', { cookie: memberCookie() })
    ).json()) as OrgsBody
    expect(list.organizations).toEqual([expect.objectContaining({ role: 'member' })])

    const first = await call('POST', '/auth-link/organizations/invite', {
      cookie: ownerCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'pending@orgs.test' },
    })
    expect(first.status).toBe(201)
    const duplicatePending = await call('POST', '/auth-link/organizations/invite', {
      cookie: ownerCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'pending@orgs.test' },
    })
    expect(duplicatePending.status).toBe(409)
  })

  it('a concurrent membership race lands exactly one row (compound unique index)', async () => {
    // Two concurrent creates for the same (user, organization): the
    // sequential check-then-insert cannot arbitrate this window; the
    // database-level unique index can (issue #21). Exactly one of the
    // two attempts survives, and the membership table holds no
    // duplicates.
    const member = await payload.find({
      collection: 'users',
      where: { email: { equals: 'member@orgs.test' } },
      limit: 1,
      overrideAccess: true,
    })
    const memberId = String(member.docs[0]?.id)
    expect(memberId).not.toBe('undefined')

    const races = await Promise.allSettled([
      payload.create({
        collection: 'memberships',
        data: { user: memberId, organization: orgId, role: 'member' },
        overrideAccess: true,
      }),
      payload.create({
        collection: 'memberships',
        data: { user: memberId, organization: orgId, role: 'member' },
        overrideAccess: true,
      }),
    ])
    const fulfilled = races.filter((entry) => entry.status === 'fulfilled').length
    expect(fulfilled).toBeLessThanOrEqual(1)
    const rows = await payload.find({
      collection: 'memberships',
      where: { user: { equals: memberId } },
      pagination: false,
      overrideAccess: true,
    })
    expect(rows.totalDocs).toBe(1)
  })

  it('refuses organization creation while impersonating (req.user is populated)', async () => {
    // The endpoint verifies the session explicitly, but the
    // impersonation deny reads `req.user` — proof that Payload's
    // strategy populates it for custom endpoints too (issue #21).
    // An operator acting AS a user must not mint organizations that
    // the user then owns.
    const impersonated = stub.issue({
      sessionId: `sess-imp-create-org-${Math.random()}`,
      providerUserId: 'stub-owner',
      email: 'owner@orgs.test',
      expiresAt: new Date(Date.now() + 3600_000),
      actorProviderUserId: 'stub-outsider',
    })
    const response = await call('POST', '/auth-link/organizations', {
      cookie: impersonated,
      csrf: true,
      body: { name: 'Shadow Org', slug: 'shadow-org' },
    })
    expect(response.status).toBe(403)
    expect(((await response.json()) as { error: string }).error).toContain('while impersonating')
    // And the organization was not created.
    const list = (await (
      await call('GET', '/auth-link/organizations', { cookie: impersonated })
    ).json()) as OrgsBody
    expect(list.organizations.some((org) => org.slug === 'shadow-org')).toBe(false)
  })

  it('refuses invites from non-managers', async () => {
    const refused = await call('POST', '/auth-link/organizations/invite', {
      cookie: memberCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'outsider@orgs.test', role: 'member' },
    })
    expect(refused.status).toBe(403)
  })

  it('holds invites for unknown emails until that user accepts', async () => {
    const invited = await call('POST', '/auth-link/organizations/invite', {
      cookie: ownerCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'outsider@orgs.test' },
    })
    expect(invited.status).toBe(201)
    const body = (await invited.json()) as { invitation: { id: string; status: string } }
    // The outsider is already a Payload user (JIT above) so this one
    // lands active; for the pending path use a fresh never-seen address.
    expect(body.invitation.status).toBe('active')

    const pending = await call('POST', '/auth-link/organizations/invite', {
      cookie: ownerCookie(),
      csrf: true,
      body: { organizationId: orgId, email: 'future@orgs.test', role: 'admin' },
    })
    expect(pending.status).toBe(201)
    const pendingBody = (await pending.json()) as { invitation: { id: string; status: string } }
    expect(pendingBody.invitation.status).toBe('invited')

    // Somebody else cannot accept it.
    const stolen = await call('POST', '/auth-link/organizations/accept', {
      cookie: memberCookie(),
      csrf: true,
      body: { invitationId: pendingBody.invitation.id },
    })
    expect(stolen.status).toBe(403)

    // The future user signs in (JIT provisions with that email) and accepts.
    const futureCookie = stub.issue({
      sessionId: 'sess-future',
      providerUserId: 'stub-future',
      email: 'future@orgs.test',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const listBefore = (await (
      await call('GET', '/auth-link/organizations', { cookie: futureCookie })
    ).json()) as OrgsBody
    expect(listBefore.invitations).toEqual([
      expect.objectContaining({ id: pendingBody.invitation.id, role: 'admin' }),
    ])
    const accepted = await call('POST', '/auth-link/organizations/accept', {
      cookie: futureCookie,
      csrf: true,
      body: { invitationId: pendingBody.invitation.id },
    })
    expect(accepted.status).toBe(200)
    const listAfter = (await (
      await call('GET', '/auth-link/organizations', { cookie: futureCookie })
    ).json()) as OrgsBody
    expect(listAfter.organizations).toEqual([expect.objectContaining({ id: orgId, role: 'admin' })])
  })

  it('answers requireOrgRole from live membership data', async () => {
    const owner = await payload.find({
      collection: 'users',
      where: { email: { equals: 'owner@orgs.test' } },
      overrideAccess: true,
    })
    const ownerId = String(owner.docs[0]?.id)
    const wiredOrgs = {
      organizationsCollection: 'organizations',
      membershipsCollection: 'memberships',
      ssoProviders: [],
      orgRoles: ['owner', 'admin', 'member'].map((value): Role => {
        const parsed = parseRole(value)
        if (parsed.isErr()) {
          throw parsed.error
        }
        return parsed.value
      }),
    }
    const ownerRole = wiredOrgs.orgRoles[0]
    if (ownerRole === undefined) {
      throw new Error('fixture roles missing')
    }
    const allowed = await requireOrgRole(
      { payload, user: { id: ownerId } } as unknown as PayloadRequest,
      wiredOrgs,
      { organizationId: orgId, roles: [ownerRole] }
    )
    expect(allowed).toBe(true)
    const denied = await requireOrgRole(
      { payload, user: null } as unknown as PayloadRequest,
      wiredOrgs,
      { organizationId: orgId, roles: [ownerRole] }
    )
    expect(denied).toBe(false)
  })
})
