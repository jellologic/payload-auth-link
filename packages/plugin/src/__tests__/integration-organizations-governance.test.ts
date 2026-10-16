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
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type PayloadRequest,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import type { AuditEvent } from '../options.js'
import { createLocalRequest } from './payload-request.js'
import { createStubProvider } from './stub-provider.js'

/**
 * SQLite in memory by default. `ORG_PG_URL` (a disposable database)
 * runs the same suite on Postgres, whose transactions and foreign keys
 * SQLite in memory does not exercise: CI's migration-fixture job does.
 */
const ORG_PG_URL = process.env.ORG_PG_URL
function database() {
  return ORG_PG_URL === undefined
    ? sqliteAdapter({ client: { url: ':memory:' } })
    : postgresAdapter({ pool: { connectionString: ORG_PG_URL }, push: true })
}

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
  loner: 'loner@gov.test',
  operator: 'operator@gov.test',
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
  opts: {
    cookie?: string
    csrf?: boolean
    body?: unknown
    /** A raw body sent verbatim with this content type (malformed-input probes). */
    raw?: { text: string; contentType: string }
  } = {}
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
  if (opts.raw !== undefined) {
    headers['content-type'] = opts.raw.contentType
  }
  const body =
    opts.raw !== undefined
      ? opts.raw.text
      : opts.body === undefined
        ? undefined
        : JSON.stringify(opts.body)
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body }),
    }),
  })
  let parsed: unknown
  try {
    parsed = await response.json()
  } catch {
    parsed = null
  }
  return { status: response.status, body: parsed }
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
    db: database(),
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
  for (const person of [
    'owner',
    'victim',
    'admin',
    'member',
    'outsider',
    'loner',
    'operator',
  ] as const) {
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

  it('create and invite answer 403 with the onAudit record when the target does not verify', async () => {
    // An impersonated session whose target cannot be verified (an
    // unverified, unprovisioned address): the endpoints used to stop
    // at the session gate with a bare 401 and no denial record.
    const unverifiedTarget = () =>
      stub.issue({
        sessionId: `sess-unverified-imp-${Math.random()}`,
        providerUserId: 'stub-unverified-target',
        email: 'unverified-target@gov.test',
        emailVerified: false,
        expiresAt: new Date(Date.now() + 3600_000),
        actorProviderUserId: 'stub-outsider',
      })
    const cases = [
      {
        endpoint: '/auth-link/organizations',
        operation: 'create',
        body: { name: 'Shadow', slug: 'shadow-unverified' },
      },
      {
        endpoint: '/auth-link/organizations/invite',
        operation: 'invite',
        body: { organizationId: orgA, email: 'shadow-unverified@gov.test', role: 'member' },
      },
      {
        endpoint: '/auth-link/organizations/accept',
        operation: 'accept',
        body: { invitationId: '1' },
      },
    ]
    for (const { endpoint, operation, body } of cases) {
      const before = audit.length
      const refused = await call('POST', endpoint, { cookie: unverifiedTarget(), body })
      expect(refused.status).toBe(403)
      expect((refused.body as { error: string }).error).toContain('while impersonating')
      const event = audit.slice(before).find((entry) => entry.fields.endpoint === endpoint)
      expect(event?.message).toBe('impersonated operation')
      expect(event?.fields).toMatchObject({
        operation,
        denied: true,
        actorKind: 'provider-only',
        actorProviderUserId: 'stub-outsider',
      })
    }
    const shadow = await payload.find({
      collection: 'organizations',
      where: { slug: { equals: 'shadow-unverified' } },
      overrideAccess: true,
    })
    expect(shadow.totalDocs).toBe(0)
    // The same session without an actor stays a plain 401.
    const plain = await call('POST', '/auth-link/organizations', {
      cookie: stub.issue({
        sessionId: `sess-unverified-plain-${Math.random()}`,
        providerUserId: 'stub-unverified-target',
        email: 'unverified-target@gov.test',
        emailVerified: false,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
      body: { name: 'Shadow', slug: 'shadow-unverified' },
    })
    expect(plain.status).toBe(401)
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

describe('the last-owner guard holds under concurrency', () => {
  async function twoOwnerOrg(slug: string): Promise<{ id: string; rows: [Row, Row] }> {
    const id = await createOrg('victim', slug)
    await payload.create({
      collection: 'memberships',
      data: {
        organization: idValue(id),
        user: idValue(userId('outsider')),
        role: 'owner',
        status: 'active',
      },
      overrideAccess: true,
    })
    return {
      id,
      rows: [await requireMembership('victim', id), await requireMembership('outsider', id)],
    }
  }

  async function activeOwners(organizationId: string): Promise<number> {
    const found = await payload.count({
      collection: 'memberships',
      where: {
        and: [
          { organization: { equals: idValue(organizationId) } },
          { role: { equals: 'owner' } },
          { status: { equals: 'active' } },
        ],
      },
      overrideAccess: true,
    })
    return found.totalDocs
  }

  /**
   * At most one of two racing ownership removals may win, and the
   * owners left are exactly those whose removal was refused. Both may
   * be refused (each re-checks after its write and sees the other's
   * removal; without transactions each then restores its own row):
   * safe, and never zero owners.
   */
  function expectOneOwnerKept(statuses: number[], owners: number): void {
    for (const status of statuses) {
      expect([200, 409]).toContain(status)
    }
    const won = statuses.filter((status) => status === 200).length
    expect(won).toBeLessThanOrEqual(1)
    expect(owners).toBe(2 - won)
  }

  it('two owners removing each other at once leave one owner', async () => {
    const { id, rows } = await twoOwnerOrg('race-delete')
    const [a, b] = await Promise.all([
      call('DELETE', `/memberships/${rows[1].id}`, { cookie: cookieFor('victim') }),
      call('DELETE', `/memberships/${rows[0].id}`, { cookie: cookieFor('outsider') }),
    ])
    expectOneOwnerKept([a.status, b.status], await activeOwners(id))
  })

  it('two owners demoting each other at once leave one owner', async () => {
    const { id, rows } = await twoOwnerOrg('race-demote')
    const [a, b] = await Promise.all([
      call('PATCH', `/memberships/${rows[1].id}`, {
        cookie: cookieFor('victim'),
        body: { role: 'member' },
      }),
      call('PATCH', `/memberships/${rows[0].id}`, {
        cookie: cookieFor('outsider'),
        body: { role: 'member' },
      }),
    ])
    expectOneOwnerKept([a.status, b.status], await activeOwners(id))
  })

  it('concurrent trusted Local-API deletes are held to it too', async () => {
    const { id, rows } = await twoOwnerOrg('race-local')
    const results = await Promise.allSettled(
      rows.map((row) =>
        payload.delete({ collection: 'memberships', id: row.id, overrideAccess: true })
      )
    )
    expectOneOwnerKept(
      results.map((result) => (result.status === 'fulfilled' ? 200 : 409)),
      await activeOwners(id)
    )
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

  it("an org admin cannot delete the organization (it would remove the owners' rows)", async () => {
    // `owner` stepped down to admin above; `admin` is now the owner.
    const ownerRow = await requireMembership('owner', orgA)
    expect(ownerRow.role).toBe('admin')
    const byId = await call('DELETE', `/organizations/${orgA}`, { cookie: cookieFor('owner') })
    expect(byId.status).toBe(403)
    const bulk = await call('DELETE', `/organizations?where[id][equals]=${orgA}`, {
      cookie: cookieFor('owner'),
    })
    expect(bulk.status).not.toBe(500)
    const org = await payload.find({
      collection: 'organizations',
      where: { id: { equals: idValue(orgA) } },
      overrideAccess: true,
    })
    expect(org.totalDocs).toBe(1)
    expect((await requireMembership('admin', orgA)).role).toBe('owner')
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

describe('organization collection access paths', () => {
  it('bulk update/delete never reach organizations the caller does not manage', async () => {
    const victim = await payload.create({
      collection: 'organizations',
      data: { name: 'Victim Corp', slug: 'victim-corp' },
      overrideAccess: true,
    })
    // The admin manages org A. A bulk PATCH (no id) carrying an
    // `organization` key naming org A must not unlock other tenants.
    const forged = await call('PATCH', '/organizations?where[slug][equals]=victim-corp', {
      cookie: cookieFor('admin'),
      body: { organization: idValue(orgA), name: 'Hijacked', verifiedDomains: [] },
    })
    expect(forged.status).not.toBe(500)
    const forgedDelete = await call('DELETE', '/organizations?where[slug][equals]=victim-corp', {
      cookie: cookieFor('admin'),
    })
    expect(forgedDelete.status).not.toBe(500)
    const after = await payload.findByID({
      collection: 'organizations',
      id: victim.id,
      depth: 0,
      overrideAccess: true,
    })
    expect(after.name).toBe('Victim Corp')
    // A bulk update scoped to an organization the caller manages works.
    const own = await call('PATCH', `/organizations?where[id][equals]=${orgA}`, {
      cookie: cookieFor('admin'),
      body: { name: 'org-a' },
    })
    expect(own.status).toBe(200)
    expect((own.body as { docs: unknown[] }).docs).toHaveLength(1)
    await payload.delete({ collection: 'organizations', id: victim.id, overrideAccess: true })
  })

  it('read: anonymous callers and users with no membership see nothing', async () => {
    expect((await call('GET', '/organizations')).status).toBe(403)
    expect((await call('GET', '/organizations', { cookie: cookieFor('loner') })).status).toBe(403)
    const asMember = await call('GET', '/organizations?depth=0', { cookie: cookieFor('member') })
    expect(asMember.status).toBe(200)
    const ids = (asMember.body as { docs: { id: unknown }[] }).docs.map((doc) => String(doc.id))
    expect(ids).toEqual([orgA])
  })

  it('membership read: a user with no organization sees only their own rows', async () => {
    const own = await call('GET', '/memberships?depth=0', { cookie: cookieFor('loner') })
    expect(own.status).toBe(200)
    expect((own.body as { docs: unknown[] }).docs).toEqual([])
  })

  it('create over REST: refused anonymously and while impersonating', async () => {
    const anonymous = await call('POST', '/organizations', { body: { name: 'Anon', slug: 'anon' } })
    expect(anonymous.status).toBe(403)
    const impersonated = await call('POST', '/organizations', {
      cookie: cookieFor('loner', 'stub-outsider'),
      body: { name: 'Shadow', slug: 'shadow' },
    })
    expect(impersonated.status).toBe(403)
    const found = await payload.find({
      collection: 'organizations',
      where: { slug: { in: ['anon', 'shadow'] } },
      overrideAccess: true,
    })
    expect(found.totalDocs).toBe(0)
  })

  it('create over REST seeds the creator as owner; an update does not re-seed', async () => {
    const created = await call('POST', '/organizations', {
      cookie: cookieFor('loner'),
      body: { name: 'Loner Org', slug: 'loner-org' },
    })
    expect(created.status).toBe(201)
    const id = String((created.body as { doc: { id: unknown } }).doc.id)
    expect((await requireMembership('loner', id)).role).toBe('owner')
    const renamed = await call('PATCH', `/organizations/${id}`, {
      cookie: cookieFor('loner'),
      body: { name: 'Loner Org Renamed' },
    })
    expect(renamed.status).toBe(200)
    const rows = await payload.find({
      collection: 'memberships',
      where: { organization: { equals: idValue(id) } },
      overrideAccess: true,
    })
    expect(rows.totalDocs).toBe(1)
  })

  it('verified domains are operator-only: org owners cannot claim one', async () => {
    const domains = async (id: string): Promise<unknown[]> => {
      const org = await payload.findByID({
        collection: 'organizations',
        id,
        depth: 0,
        overrideAccess: true,
      })
      return ((org.verifiedDomains ?? []) as { domain: string }[]).map((entry) => entry.domain)
    }
    // Any signed-in user may create an organization, but a domain
    // claim on it is dropped: otherwise `gmail.com` would satisfy the
    // SSO domain gate for every Gmail address.
    const claimed = await call('POST', '/organizations', {
      cookie: cookieFor('member'),
      body: { name: 'Claim', slug: 'claim-gmail', verifiedDomains: [{ domain: 'gmail.com' }] },
    })
    expect(claimed.status).toBe(201)
    const claimedId = String((claimed.body as { doc: { id: unknown } }).doc.id)
    expect(await domains(claimedId)).toEqual([])
    // Nor can an org manager add one later.
    const patched = await call('PATCH', `/organizations/${claimedId}`, {
      cookie: cookieFor('member'),
      body: { verifiedDomains: [{ domain: 'gmail.com' }] },
    })
    expect([200, 403]).toContain(patched.status)
    expect(await domains(claimedId)).toEqual([])
    const sso = await payload.find({
      collection: 'organizations',
      where: { 'verifiedDomains.domain': { equals: 'gmail.com' } },
      overrideAccess: true,
    })
    expect(sso.totalDocs).toBe(0)
    await payload.delete({ collection: 'organizations', id: claimedId, overrideAccess: true })
  })

  it('verified domains: a role-managing operator may set them (validated), not while impersonating', async () => {
    await payload.update({
      collection: 'users',
      id: idValue(userId('operator')),
      data: { roles: ['admin'] },
      overrideAccess: true,
    })
    // The operator also needs the org-level right to update org A.
    await payload.create({
      collection: 'memberships',
      data: {
        organization: idValue(orgA),
        user: idValue(userId('operator')),
        role: 'admin',
        status: 'active',
      },
      overrideAccess: true,
    })
    const bad = await call('PATCH', `/organizations/${orgA}`, {
      cookie: cookieFor('operator'),
      body: { verifiedDomains: [{ domain: 'Not A Domain' }] },
    })
    expect(bad.status).toBe(400)
    const impersonated = await call('PATCH', `/organizations/${orgA}`, {
      cookie: cookieFor('operator', 'stub-outsider'),
      body: { verifiedDomains: [{ domain: 'shadow.test' }] },
    })
    expect(impersonated.status).toBe(403)
    const good = await call('PATCH', `/organizations/${orgA}`, {
      cookie: cookieFor('operator'),
      body: { verifiedDomains: [{ domain: 'gov.test' }] },
    })
    expect(good.status).toBe(200)
    const org = await payload.findByID({
      collection: 'organizations',
      id: orgA,
      depth: 0,
      overrideAccess: true,
    })
    expect(((org.verifiedDomains ?? []) as { domain: string }[]).map((e) => e.domain)).toEqual([
      'gov.test',
    ])
    // The org's own admin still cannot change them.
    const orgAdmin = await call('PATCH', `/organizations/${orgA}`, {
      cookie: cookieFor('admin'),
      body: { verifiedDomains: [{ domain: 'evil.test' }] },
    })
    expect(orgAdmin.status).toBe(200)
    const still = await payload.findByID({
      collection: 'organizations',
      id: orgA,
      depth: 0,
      overrideAccess: true,
    })
    expect(((still.verifiedDomains ?? []) as { domain: string }[]).map((e) => e.domain)).toEqual([
      'gov.test',
    ])
  })

  it('a bulk organization delete cascades every tenant; the owner guard does not block it', async () => {
    const ids: string[] = []
    for (const slug of ['bulk-1', 'bulk-2']) {
      const org = await payload.create({
        collection: 'organizations',
        data: { name: slug, slug },
        overrideAccess: true,
      })
      ids.push(String(org.id))
      await payload.create({
        collection: 'memberships',
        data: {
          organization: org.id,
          user: idValue(userId('loner')),
          role: 'owner',
          status: 'active',
        },
        overrideAccess: true,
      })
    }
    const removed = await payload.delete({
      collection: 'organizations',
      where: { slug: { in: ['bulk-1', 'bulk-2'] } },
      overrideAccess: true,
    })
    expect(removed.errors).toEqual([])
    expect(removed.docs).toHaveLength(2)
    const left = await payload.find({
      collection: 'memberships',
      where: { organization: { in: ids.map(idValue) } },
      overrideAccess: true,
    })
    expect(left.totalDocs).toBe(0)
  })
})

describe('organization endpoints: malformed input', () => {
  const invalidJson = { text: '{"name": ', contentType: 'application/json' }

  it('create: invalid, non-object, or incomplete bodies are 400', async () => {
    for (const opts of [
      { raw: invalidJson },
      { raw: { text: '["name","slug"]', contentType: 'application/json' } },
      { body: { slug: 'no-name' } },
      { body: { name: 'No Slug' } },
      { body: { name: '   ', slug: 'blank-name' } },
      { body: { name: 'Bad Slug', slug: 'Bad Slug' } },
      { body: { name: 'Dash', slug: '-leading-dash' } },
    ]) {
      const response = await call('POST', '/auth-link/organizations', {
        cookie: cookieFor('loner'),
        ...opts,
      })
      expect(response.status).toBe(400)
    }
  })

  it('create: a duplicate slug is a 400, not a 500, and leaves no stray membership', async () => {
    const before = await payload.count({ collection: 'memberships', overrideAccess: true })
    const duplicate = await call('POST', '/auth-link/organizations', {
      cookie: cookieFor('loner'),
      body: { name: 'Again', slug: 'org-a' },
    })
    expect(duplicate.status).toBe(400)
    expect((duplicate.body as { error: string }).error).toBe('organization could not be created')
    const after = await payload.count({ collection: 'memberships', overrideAccess: true })
    expect(after.totalDocs).toBe(before.totalDocs)
  })

  it('create: a JSON body sent without a JSON content type is still read', async () => {
    const created = await call('POST', '/auth-link/organizations', {
      cookie: cookieFor('loner'),
      raw: {
        text: JSON.stringify({ name: 'Plain', slug: 'plain-org' }),
        contentType: 'text/plain',
      },
    })
    expect(created.status).toBe(201)
  })

  it('invite: invalid bodies, bad emails, and unknown roles are 400', async () => {
    for (const opts of [
      { raw: invalidJson },
      { body: { email: 'x@gov.test', role: 'member' } },
      { body: { organizationId: orgA, role: 'member' } },
      { body: { organizationId: orgA, email: 'not-an-email', role: 'member' } },
      { body: { organizationId: orgA, email: 'x@gov.test', role: 'emperor' } },
      { body: { organizationId: orgA, email: 'x@gov.test', role: 'NOT A ROLE!' } },
    ]) {
      const response = await call('POST', '/auth-link/organizations/invite', {
        cookie: cookieFor('admin'),
        ...opts,
      })
      expect(response.status).toBe(400)
    }
    const pending = await payload.count({
      collection: 'memberships',
      where: { invitedEmail: { equals: 'x@gov.test' } },
      overrideAccess: true,
    })
    expect(pending.totalDocs).toBe(0)
  })

  it('invite: without a role, the invitee gets the lowest org role', async () => {
    const invited = await call('POST', '/auth-link/organizations/invite', {
      cookie: cookieFor('admin'),
      body: { organizationId: orgA, email: 'lowest@gov.test' },
    })
    expect(invited.status).toBe(201)
    expect((invited.body as { invitation: { role: string } }).invitation.role).toBe('member')
  })

  it('invite: plain members and non-members are refused', async () => {
    expect((await invite('member', orgA, 'm@gov.test', 'member')).status).toBe(403)
    expect((await invite('loner', orgA, 'm@gov.test', 'member')).status).toBe(403)
  })

  it('accept: an invitee who already joined another way gets a 409, not a 500', async () => {
    const email = 'late@gov.test'
    const late = () =>
      stub.issue({
        sessionId: `sess-late-${Math.random()}`,
        providerUserId: 'stub-late',
        email,
        expiresAt: new Date(Date.now() + 3600_000),
      })
    // Invited before they have an account: the invitation waits.
    const pending = await call('POST', '/auth-link/organizations/invite', {
      cookie: cookieFor('admin'),
      body: { organizationId: orgA, email, role: 'member' },
    })
    expect(pending.status).toBe(201)
    const invitationId = (pending.body as { invitation: { id: string } }).invitation.id
    expect((await call('GET', '/auth-link/session', { cookie: late() })).status).toBe(200)
    const found = await payload.find({
      collection: 'users',
      where: { email: { equals: email } },
      overrideAccess: true,
    })
    const lateId = String(found.docs[0]?.id)
    // Meanwhile a manager adds them directly.
    const added = await call('POST', '/memberships', {
      cookie: cookieFor('admin'),
      body: { organization: idValue(orgA), user: idValue(lateId), role: 'member' },
    })
    expect(added.status).toBe(201)
    const accepted = await call('POST', '/auth-link/organizations/accept', {
      cookie: late(),
      body: { invitationId },
    })
    expect(accepted.status).toBe(409)
    const rows = await payload.find({
      collection: 'memberships',
      where: {
        and: [{ organization: { equals: idValue(orgA) } }, { user: { equals: idValue(lateId) } }],
      },
      overrideAccess: true,
    })
    expect(rows.totalDocs).toBe(1)
  })

  it('accept: missing, unknown, foreign, and already-active rows are refused', async () => {
    const missing = await call('POST', '/auth-link/organizations/accept', {
      cookie: cookieFor('loner'),
      body: {},
    })
    expect(missing.status).toBe(400)
    const malformed = await call('POST', '/auth-link/organizations/accept', {
      cookie: cookieFor('loner'),
      raw: invalidJson,
    })
    expect(malformed.status).toBe(400)
    for (const invitationId of ['987654', 'not-an-id']) {
      const unknown = await call('POST', '/auth-link/organizations/accept', {
        cookie: cookieFor('loner'),
        body: { invitationId },
      })
      expect(unknown.status).toBe(403)
    }
    // The invitee's pending invitation: another signed-in user cannot
    // claim it (the verified email is the authority, not the body).
    const pending = await payload.find({
      collection: 'memberships',
      where: { invitedEmail: { equals: people.invitee } },
      overrideAccess: true,
    })
    const invitationId = String(pending.docs[0]?.id)
    const foreign = await call('POST', '/auth-link/organizations/accept', {
      cookie: cookieFor('loner'),
      body: { invitationId },
    })
    expect(foreign.status).toBe(403)
    const row = await payload.findByID({
      collection: 'memberships',
      id: invitationId,
      depth: 0,
      overrideAccess: true,
    })
    expect(row.status).toBe('invited')
    expect(row.user ?? null).toBeNull()
    // An active membership is not an invitation.
    const active = await requireMembership('member', orgA)
    const replay = await call('POST', '/auth-link/organizations/accept', {
      cookie: cookieFor('member'),
      body: { invitationId: active.id },
    })
    expect(replay.status).toBe(403)
  })
})

describe('organization endpoints called without a Payload-populated req.user', () => {
  function endpoint(path: string, method: string) {
    const found = (config.endpoints ?? []).find(
      (candidate) => candidate.path === path && candidate.method === method
    )
    if (found === undefined) {
      throw new Error(`endpoint missing: ${method} ${path}`)
    }
    return found
  }

  async function bareRequest(person: Person, extra: Partial<PayloadRequest> = {}) {
    return createLocalRequest(payload, {
      method: 'POST',
      headers: new Headers({
        cookie: cookieFor(person),
        origin: ORIGIN,
        'x-auth-link-csrf': '1',
      }),
      ...extra,
    })
  }

  it('create still seeds the verified caller as owner', async () => {
    const req = await bareRequest('loner', { data: { name: 'Bare', slug: 'bare-org' } })
    expect(req.user ?? null).toBeNull()
    const response = await endpoint('/auth-link/organizations', 'post').handler(req)
    expect(response.status).toBe(201)
    const { organization } = (await response.json()) as { organization: { id: string } }
    expect((await requireMembership('loner', organization.id)).role).toBe('owner')
  })

  it('create falls back to req.json(), and a request with no body is a 400', async () => {
    const viaJson = await bareRequest('loner', {
      json: () => Promise.resolve({ name: 'Via Json', slug: 'via-json' }),
    })
    expect((await endpoint('/auth-link/organizations', 'post').handler(viaJson)).status).toBe(201)
    const empty = await bareRequest('loner')
    expect((await endpoint('/auth-link/organizations', 'post').handler(empty)).status).toBe(400)
  })

  it('listing reports an unreadable organization with null name and slug, not a 500', async () => {
    const req = await bareRequest('member')
    req.payload = new Proxy(payload, {
      get(target, key, receiver) {
        if (key === 'findByID') {
          return (args: Parameters<Payload['findByID']>[0]) =>
            args.collection === 'organizations'
              ? Promise.reject(new Error('storage down'))
              : target.findByID(args)
        }
        return Reflect.get(target, key, receiver) as unknown
      },
    })
    const response = await endpoint('/auth-link/organizations', 'get').handler(req)
    expect(response.status).toBe(200)
    const listed = (await response.json()) as {
      organizations: { id: string; name: string | null; slug: string | null; role: string }[]
    }
    expect(listed.organizations).toContainEqual({
      id: orgA,
      name: null,
      slug: null,
      role: 'member',
    })
  })

  it('invite fails closed (500, nothing written) when the user lookup errors', async () => {
    const req = await bareRequest('admin', {
      data: { organizationId: orgA, email: 'lookup-fails@gov.test', role: 'member' },
    })
    req.payload = new Proxy(payload, {
      get(target, key, receiver) {
        if (key === 'find') {
          return (args: Parameters<Payload['find']>[0]) =>
            args.collection === 'users' && JSON.stringify(args.where).includes('lookup-fails')
              ? Promise.reject(new Error('storage down'))
              : target.find(args)
        }
        return Reflect.get(target, key, receiver) as unknown
      },
    })
    const response = await endpoint('/auth-link/organizations/invite', 'post').handler(req)
    expect(response.status).toBe(500)
    const pending = await payload.count({
      collection: 'memberships',
      where: { invitedEmail: { equals: 'lookup-fails@gov.test' } },
      overrideAccess: true,
    })
    expect(pending.totalDocs).toBe(0)
  })

  it('an unreadable caller record is a 401 on every endpoint, never a pass', async () => {
    const failingUserReads = (req: PayloadRequest) => {
      req.payload = new Proxy(payload, {
        get(target, key, receiver) {
          if (key === 'findByID') {
            return (args: Parameters<Payload['findByID']>[0]) =>
              args.collection === 'users'
                ? Promise.reject(new Error('storage down'))
                : target.findByID(args)
          }
          return Reflect.get(target, key, receiver) as unknown
        },
      })
      return req
    }
    const before = await payload.count({ collection: 'organizations', overrideAccess: true })
    const cases = [
      { path: '/auth-link/organizations', method: 'get', data: undefined },
      { path: '/auth-link/organizations', method: 'post', data: { name: 'X', slug: 'x-org' } },
      {
        path: '/auth-link/organizations/invite',
        method: 'post',
        data: { organizationId: orgA, email: 'unread@gov.test', role: 'member' },
      },
      { path: '/auth-link/organizations/accept', method: 'post', data: { invitationId: '1' } },
    ]
    for (const { path, method, data } of cases) {
      const req = failingUserReads(await bareRequest('admin', data === undefined ? {} : { data }))
      expect((await endpoint(path, method).handler(req)).status).toBe(401)
    }
    const after = await payload.count({ collection: 'organizations', overrideAccess: true })
    expect(after.totalDocs).toBe(before.totalDocs)
  })
})
