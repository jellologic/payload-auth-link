/**
 * Organization governance (CAP-11 hardening): real Payload (SQLite in
 * memory) with organizations enabled, driven through Payload's own
 * REST routes and the plugin's endpoints via `handleEndpoints`.
 *
 * Each security proof fails without its fix:
 * - a membership cannot be relocated to another organization or
 *   re-pointed at another user (REST field access AND the trusted
 *   Local API, which only the integrity hook covers);
 * - role writes never exceed the caller's own org role;
 * - organization management is refused (and audited) while
 *   impersonating — invite, accept, and every membership write;
 * - an organization keeps at least one owner;
 * - deleting an organization cascades its memberships cleanly.
 * It also walks the membership access paths (tenant-scoped reads,
 * unauthenticated / non-manager / malformed writes) and the
 * endpoints' CSRF and session gates.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import type { AuditEvent } from '../options.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://orgs-governance.test'
const SECRET = 'organizations-governance-secret!!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()
const audit: AuditEvent[] = []

const people = {
  owner: 'owner@gov.test',
  victim: 'victim@gov.test',
  admin: 'admin@gov.test',
  member: 'member@gov.test',
  outsider: 'outsider@gov.test',
  invitee: 'invitee@gov.test',
} as const
type Person = keyof typeof people

function cookieFor(person: Person, actorProviderUserId?: string): string {
  return stub.issue({
    sessionId: `sess-${person}-${Math.random()}`,
    providerUserId: `stub-${person}`,
    email: people[person],
    expiresAt: new Date(Date.now() + 3600_000),
    ...(actorProviderUserId === undefined ? {} : { actorProviderUserId }),
  })
}

async function call(
  method: string,
  path: string,
  opts: { cookie?: string; csrf?: boolean; body?: unknown } = {}
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = {}
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.csrf !== false) {
    headers['x-auth-link-csrf'] = '1'
    headers.origin = ORIGIN
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body }
}

const userIds: Partial<Record<Person, string>> = {}
function userId(person: Person): string {
  const id = userIds[person]
  if (id === undefined) {
    throw new Error(`user missing: ${person}`)
  }
  return id
}

/** SQLite ids are numbers; relationship writes need the runtime type. */
function idValue(id: string): string | number {
  return /^\d+$/.test(id) ? Number(id) : id
}

function relation(value: unknown): string | null {
  if (typeof value === 'string' || typeof value === 'number') {
    return String(value)
  }
  if (typeof value === 'object' && value !== null && 'id' in value) {
    const id = value.id
    return typeof id === 'string' || typeof id === 'number' ? String(id) : null
  }
  return null
}

type Row = { id: string; organization: string | null; user: string | null; role: string }

async function membershipOf(person: Person, organizationId: string): Promise<Row | null> {
  const found = await payload.find({
    collection: 'memberships',
    where: {
      and: [
        { user: { equals: idValue(userId(person)) } },
        { organization: { equals: idValue(organizationId) } },
      ],
    },
    depth: 0,
    overrideAccess: true,
  })
  const doc = found.docs[0] as Record<string, unknown> | undefined
  if (doc === undefined) {
    return null
  }
  return {
    id: String(doc.id),
    organization: relation(doc.organization),
    user: relation(doc.user),
    role: String(doc.role),
  }
}

async function requireMembership(person: Person, organizationId: string): Promise<Row> {
  const row = await membershipOf(person, organizationId)
  if (row === null) {
    throw new Error(`membership missing: ${person} in ${organizationId}`)
  }
  return row
}

async function createOrg(person: Person, slug: string): Promise<string> {
  const created = await call('POST', '/auth-link/organizations', {
    cookie: cookieFor(person),
    body: { name: slug, slug },
  })
  expect(created.status).toBe(201)
  return (created.body as { organization: { id: string } }).organization.id
}

async function invite(
  by: Person,
  organizationId: string,
  email: string,
  role: string
): Promise<{ status: number; body: unknown }> {
  return call('POST', '/auth-link/organizations/invite', {
    cookie: cookieFor(by),
    body: { organizationId, email, role },
  })
}

let orgA = ''
let orgB = ''

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
        onAudit: (event) => {
          audit.push(event)
        },
      }),
    ],
  })
  payload = await getPayload({ config })
  for (const person of ['owner', 'victim', 'admin', 'member', 'outsider'] as const) {
    expect((await call('GET', '/auth-link/session', { cookie: cookieFor(person) })).status).toBe(
      200
    )
    const found = await payload.find({
      collection: 'users',
      where: { email: { equals: people[person] } },
      overrideAccess: true,
    })
    userIds[person] = String(found.docs[0]?.id)
  }
  // Org A: owner (owner), admin (admin), member (member).
  orgA = await createOrg('owner', 'org-a')
  expect((await invite('owner', orgA, people.admin, 'admin')).status).toBe(201)
  expect((await invite('owner', orgA, people.member, 'member')).status).toBe(201)
  // Org B: the victim tenant.
  orgB = await createOrg('victim', 'org-b')
}, 60_000)

describe('membership relocation is refused', () => {
  it('REST: an owner cannot move their own membership into another org', async () => {
    const own = await requireMembership('owner', orgA)
    const attempt = await call('PATCH', `/memberships/${own.id}`, {
      cookie: cookieFor('owner'),
      body: { organization: idValue(orgB), role: 'owner' },
    })
    // Field access drops the write (or the request is refused); either
    // way the row never leaves its tenant.
    expect([200, 403]).toContain(attempt.status)
    expect((await requireMembership('owner', orgA)).organization).toBe(orgA)
    expect(await membershipOf('owner', orgB)).toBeNull()
  })

  it('REST: a manager cannot re-point a membership at another user', async () => {
    // Org B's owner (untouched by the relocation attempt above) and a
    // plain member row to re-point.
    const seeded = await payload.create({
      collection: 'memberships',
      data: {
        organization: idValue(orgB),
        user: idValue(userId('outsider')),
        role: 'member',
        status: 'active',
      },
      overrideAccess: true,
    })
    const attempt = await call('PATCH', `/memberships/${String(seeded.id)}`, {
      cookie: cookieFor('victim'),
      body: { user: idValue(userId('member')) },
    })
    expect([200, 403]).toContain(attempt.status)
    expect((await requireMembership('outsider', orgB)).user).toBe(userId('outsider'))
    expect(await membershipOf('member', orgB)).toBeNull()
    await payload.delete({ collection: 'memberships', id: seeded.id, overrideAccess: true })
  })

  it('Local API (overrideAccess): relocation and user rewrites throw', async () => {
    const own = await requireMembership('owner', orgA)
    await expect(
      payload.update({
        collection: 'memberships',
        id: own.id,
        data: { organization: idValue(orgB) },
        overrideAccess: true,
      })
    ).rejects.toThrow(/another organization/)
    await expect(
      payload.update({
        collection: 'memberships',
        id: own.id,
        data: { user: idValue(userId('outsider')) },
        overrideAccess: true,
      })
    ).rejects.toThrow(/another user/)
    expect(await requireMembership('owner', orgA)).toMatchObject({
      organization: orgA,
      user: userId('owner'),
    })
  })
})

describe('role writes never exceed the caller', () => {
  it('an admin cannot promote themselves (or anyone) to owner', async () => {
    const own = await requireMembership('admin', orgA)
    const self = await call('PATCH', `/memberships/${own.id}`, {
      cookie: cookieFor('admin'),
      body: { role: 'owner' },
    })
    expect(self.status).toBe(403)
    expect((await requireMembership('admin', orgA)).role).toBe('admin')

    const memberRow = await requireMembership('member', orgA)
    const other = await call('PATCH', `/memberships/${memberRow.id}`, {
      cookie: cookieFor('admin'),
      body: { role: 'owner' },
    })
    expect(other.status).toBe(403)
    expect((await requireMembership('member', orgA)).role).toBe('member')
  })

  it("an admin cannot demote or remove an owner's membership", async () => {
    const ownerRow = await requireMembership('owner', orgA)
    const demote = await call('PATCH', `/memberships/${ownerRow.id}`, {
      cookie: cookieFor('admin'),
      body: { role: 'member' },
    })
    expect(demote.status).toBe(403)
    const remove = await call('DELETE', `/memberships/${ownerRow.id}`, {
      cookie: cookieFor('admin'),
    })
    expect(remove.status).toBe(403)
    expect((await requireMembership('owner', orgA)).role).toBe('owner')
  })

  it('an admin may manage roles at or below their own', async () => {
    const memberRow = await requireMembership('member', orgA)
    const up = await call('PATCH', `/memberships/${memberRow.id}`, {
      cookie: cookieFor('admin'),
      body: { role: 'admin' },
    })
    expect(up.status).toBe(200)
    const down = await call('PATCH', `/memberships/${memberRow.id}`, {
      cookie: cookieFor('admin'),
      body: { role: 'member' },
    })
    expect(down.status).toBe(200)
    expect((await requireMembership('member', orgA)).role).toBe('member')
  })

  it('a plain member cannot change any role, their own included', async () => {
    const memberRow = await requireMembership('member', orgA)
    const attempt = await call('PATCH', `/memberships/${memberRow.id}`, {
      cookie: cookieFor('member'),
      body: { role: 'owner' },
    })
    expect(attempt.status).toBe(403)
    expect((await requireMembership('member', orgA)).role).toBe('member')
  })

  it('an admin cannot invite at a role above their own', async () => {
    const refused = await invite('admin', orgA, 'boss@gov.test', 'owner')
    expect(refused.status).toBe(403)
  })

  it('a manager of one org has no write access in another', async () => {
    const victimRow = await requireMembership('victim', orgB)
    const attempt = await call('PATCH', `/memberships/${victimRow.id}`, {
      cookie: cookieFor('owner'),
      body: { role: 'member' },
    })
    expect(attempt.status).toBe(403)
    const forged = await call('POST', '/memberships', {
      cookie: cookieFor('owner'),
      body: { organization: idValue(orgB), user: idValue(userId('owner')), role: 'owner' },
    })
    expect(forged.status).toBe(403)
    expect(await membershipOf('owner', orgB)).toBeNull()
  })
})

describe('membership collection access paths', () => {
  it('create: unauthenticated, non-manager, malformed, and over-rank are refused', async () => {
    const anonymous = await call('POST', '/memberships', {
      body: { organization: idValue(orgA), user: idValue(userId('outsider')), role: 'member' },
    })
    expect(anonymous.status).toBe(403)
    const selfJoin = await call('POST', '/memberships', {
      cookie: cookieFor('outsider'),
      body: { organization: idValue(orgA), user: idValue(userId('outsider')), role: 'owner' },
    })
    expect(selfJoin.status).toBe(403)
    const malformed = await call('POST', '/memberships', {
      cookie: cookieFor('owner'),
      body: { user: idValue(userId('outsider')), role: 'member' },
    })
    expect(malformed.status).toBe(403)
    const overRank = await call('POST', '/memberships', {
      cookie: cookieFor('admin'),
      body: { organization: idValue(orgA), user: idValue(userId('outsider')), role: 'owner' },
    })
    expect(overRank.status).toBe(403)
    expect(await membershipOf('outsider', orgA)).toBeNull()
  })

  it('create: a manager may add a member at or below their rank', async () => {
    const added = await call('POST', '/memberships', {
      cookie: cookieFor('admin'),
      body: { organization: idValue(orgA), user: idValue(userId('outsider')), role: 'member' },
    })
    expect(added.status).toBe(201)
    expect((await requireMembership('outsider', orgA)).role).toBe('member')
  })

  it('read: tenant-scoped (own rows plus rows of orgs the reader belongs to)', async () => {
    const anonymous = await call('GET', '/memberships')
    expect(anonymous.status).toBe(403)
    const asMember = await call('GET', '/memberships?depth=0&limit=100', {
      cookie: cookieFor('member'),
    })
    expect(asMember.status).toBe(200)
    const orgsSeen = new Set(
      (asMember.body as { docs: { organization: unknown }[] }).docs.map((doc) =>
        relation(doc.organization)
      )
    )
    expect(orgsSeen.has(orgA)).toBe(true)
    expect(orgsSeen.has(orgB)).toBe(false)
    const victimRow = await requireMembership('victim', orgB)
    const direct = await call('GET', `/memberships/${victimRow.id}`, {
      cookie: cookieFor('member'),
    })
    expect(direct.status).not.toBe(200)
  })

  it('update/delete: unknown ids and unauthenticated callers are refused', async () => {
    const unknown = await call('PATCH', '/memberships/987654', {
      cookie: cookieFor('owner'),
      body: { role: 'member' },
    })
    expect(unknown.status).not.toBe(200)
    const unknownDelete = await call('DELETE', '/memberships/987654', {
      cookie: cookieFor('owner'),
    })
    expect(unknownDelete.status).not.toBe(200)
    const memberRow = await requireMembership('member', orgA)
    const anonymous = await call('PATCH', `/memberships/${memberRow.id}`, {
      body: { role: 'admin' },
    })
    expect(anonymous.status).toBe(403)
    const anonymousDelete = await call('DELETE', `/memberships/${memberRow.id}`)
    expect(anonymousDelete.status).toBe(403)
    expect((await requireMembership('member', orgA)).role).toBe('member')
  })

  it('delete: a manager may remove a member at or below their rank', async () => {
    const outsiderRow = await requireMembership('outsider', orgA)
    const removed = await call('DELETE', `/memberships/${outsiderRow.id}`, {
      cookie: cookieFor('admin'),
    })
    expect(removed.status).toBe(200)
    expect(await membershipOf('outsider', orgA)).toBeNull()
  })
})

describe('organization management is refused while impersonating', () => {
  // The owner's own session, driven by an operator (`stub-outsider`).
  const impersonated = () => cookieFor('owner', 'stub-outsider')

  it('invite is refused and audited', async () => {
    const before = audit.length
    const refused = await call('POST', '/auth-link/organizations/invite', {
      cookie: impersonated(),
      body: { organizationId: orgA, email: 'shadow@gov.test', role: 'owner' },
    })
    expect(refused.status).toBe(403)
    expect((refused.body as { error: string }).error).toContain('while impersonating')
    const pending = await payload.find({
      collection: 'memberships',
      where: { invitedEmail: { equals: 'shadow@gov.test' } },
      overrideAccess: true,
    })
    expect(pending.totalDocs).toBe(0)
    const event = audit
      .slice(before)
      .find((entry) => entry.fields.endpoint === '/auth-link/organizations/invite')
    expect(event?.message).toBe('impersonated operation')
    expect(event?.fields).toMatchObject({
      operation: 'invite',
      denied: true,
      actorProviderUserId: 'stub-outsider',
    })
  })

  it('accept is refused and audited', async () => {
    const pending = await invite('owner', orgA, people.invitee, 'member')
    expect(pending.status).toBe(201)
    const invitationId = (pending.body as { invitation: { id: string } }).invitation.id
    const before = audit.length
    const refused = await call('POST', '/auth-link/organizations/accept', {
      cookie: stub.issue({
        sessionId: `sess-invitee-imp-${Math.random()}`,
        providerUserId: 'stub-invitee',
        email: people.invitee,
        expiresAt: new Date(Date.now() + 3600_000),
        actorProviderUserId: 'stub-outsider',
      }),
      body: { invitationId },
    })
    expect(refused.status).toBe(403)
    const event = audit
      .slice(before)
      .find((entry) => entry.fields.endpoint === '/auth-link/organizations/accept')
    expect(event?.fields).toMatchObject({ operation: 'accept', denied: true })
    const row = await payload.findByID({
      collection: 'memberships',
      id: invitationId,
      depth: 0,
      overrideAccess: true,
    })
    expect(row.status).toBe('invited')
  })

  it('membership create/update/delete over REST are refused', async () => {
    // Org B's owner, impersonated: a manager whose writes would
    // otherwise all be allowed.
    const victimImpersonated = () => cookieFor('victim', 'stub-outsider')
    const before = audit.length
    const create = await call('POST', '/memberships', {
      cookie: victimImpersonated(),
      body: { organization: idValue(orgB), user: idValue(userId('outsider')), role: 'owner' },
    })
    expect(create.status).toBe(403)
    expect(await membershipOf('outsider', orgB)).toBeNull()
    const victimRow = await requireMembership('victim', orgB)
    const update = await call('PATCH', `/memberships/${victimRow.id}`, {
      cookie: victimImpersonated(),
      body: { role: 'member' },
    })
    expect(update.status).toBe(403)
    const remove = await call('DELETE', `/memberships/${victimRow.id}`, {
      cookie: victimImpersonated(),
    })
    expect(remove.status).toBe(403)
    expect((await requireMembership('victim', orgB)).role).toBe('owner')
    // Each attempt is audited by the collection operation hook.
    const operations = audit
      .slice(before)
      .filter((event) => event.fields.collection === 'memberships')
      .map((event) => event.fields.operation)
    expect(operations).toEqual(expect.arrayContaining(['create', 'update', 'delete']))
  })

  it('organization update/delete over REST are refused', async () => {
    const update = await call('PATCH', `/organizations/${orgA}`, {
      cookie: impersonated(),
      body: { name: 'Hijacked' },
    })
    expect(update.status).toBe(403)
    const remove = await call('DELETE', `/organizations/${orgA}`, { cookie: impersonated() })
    expect(remove.status).toBe(403)
    const org = await payload.findByID({
      collection: 'organizations',
      id: orgA,
      overrideAccess: true,
    })
    expect(org.name).toBe('org-a')
  })
})

describe('an organization keeps at least one owner', () => {
  it('the last owner cannot demote or remove themselves (409)', async () => {
    const ownerRow = await requireMembership('owner', orgA)
    const demote = await call('PATCH', `/memberships/${ownerRow.id}`, {
      cookie: cookieFor('owner'),
      body: { role: 'admin' },
    })
    expect(demote.status).toBe(409)
    const remove = await call('DELETE', `/memberships/${ownerRow.id}`, {
      cookie: cookieFor('owner'),
    })
    expect(remove.status).toBe(409)
    // Trusted Local-API writes are held to the invariant too.
    await expect(
      payload.delete({ collection: 'memberships', id: ownerRow.id, overrideAccess: true })
    ).rejects.toThrow(/at least one owner/)
    expect((await requireMembership('owner', orgA)).role).toBe('owner')
  })

  it('with a second owner in place, the first may step down', async () => {
    const adminRow = await requireMembership('admin', orgA)
    const promote = await call('PATCH', `/memberships/${adminRow.id}`, {
      cookie: cookieFor('owner'),
      body: { role: 'owner' },
    })
    expect(promote.status).toBe(200)
    const ownerRow = await requireMembership('owner', orgA)
    const stepDown = await call('PATCH', `/memberships/${ownerRow.id}`, {
      cookie: cookieFor('owner'),
      body: { role: 'admin' },
    })
    expect(stepDown.status).toBe(200)
    expect((await requireMembership('owner', orgA)).role).toBe('admin')
  })
})

describe('organization delete', () => {
  it('cascades memberships and pending invitations (no 500)', async () => {
    expect((await invite('victim', orgB, 'pending-b@gov.test', 'member')).status).toBe(201)
    expect((await invite('victim', orgB, people.member, 'member')).status).toBe(201)
    const removed = await call('DELETE', `/organizations/${orgB}`, {
      cookie: cookieFor('victim'),
    })
    expect(removed.status).toBe(200)
    const left = await payload.find({
      collection: 'memberships',
      where: { organization: { equals: idValue(orgB) } },
      overrideAccess: true,
    })
    expect(left.totalDocs).toBe(0)
    // Other tenants are untouched.
    expect(await membershipOf('member', orgA)).not.toBeNull()
  })

  it('non-managers cannot delete an organization', async () => {
    const refused = await call('DELETE', `/organizations/${orgA}`, {
      cookie: cookieFor('member'),
    })
    expect(refused.status).toBe(403)
  })
})

describe('organization endpoints: session and CSRF gates', () => {
  it('invite and accept require CSRF proof', async () => {
    const inviteNoCsrf = await call('POST', '/auth-link/organizations/invite', {
      cookie: cookieFor('owner'),
      csrf: false,
      body: { organizationId: orgA, email: 'csrf@gov.test', role: 'member' },
    })
    expect(inviteNoCsrf.status).toBe(403)
    const acceptNoCsrf = await call('POST', '/auth-link/organizations/accept', {
      cookie: cookieFor('outsider'),
      csrf: false,
      body: { invitationId: '1' },
    })
    expect(acceptNoCsrf.status).toBe(403)
  })

  it('create, invite, and accept require a session', async () => {
    const create = await call('POST', '/auth-link/organizations', {
      body: { name: 'Anon', slug: 'anon' },
    })
    expect(create.status).toBe(401)
    const inviteAnon = await call('POST', '/auth-link/organizations/invite', {
      body: { organizationId: orgA, email: 'anon@gov.test' },
    })
    expect(inviteAnon.status).toBe(401)
    const accept = await call('POST', '/auth-link/organizations/accept', {
      body: { invitationId: '1' },
    })
    expect(accept.status).toBe(401)
  })
})
