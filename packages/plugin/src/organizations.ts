import {
  InvalidConfigError,
  isRecord,
  parseEmail,
  parseRole,
  type Role,
} from '@payload-auth-link/core'
import {
  addDataAndFileToRequest,
  type Access,
  type CollectionConfig,
  type Endpoint,
  type Payload,
  type PayloadRequest,
  type Where,
} from 'payload'
import {
  forbidden,
  isImpersonating,
  jsonResponse,
  passesCsrfForChannel,
  unauthorized,
} from './access.js'
import type { WiredOptions, WiredOrganizations } from './options.js'
import { createServices } from './services.js'

/**
 * Payload-owned organizations (CAP-11, decision D1): `organizations`
 * and `memberships` collections (one role per user per org) that work
 * with every provider, because membership is a property of Payload
 * users — and Payload owns the users. A provider-native org store
 * (e.g. BA's `organization` plugin) stays a provider feature and is
 * never Payload authorization.
 *
 * The plugin stores no session state for the "active" org (invariant
 * 1): the host carries it (request param, cookie, URL) and
 * authorization asks {@link requireOrgRole} per request.
 *
 * Role semantics: `orgRoles` is ordered by privilege. The creator of
 * an organization receives the FIRST role (the owner role —
 * `'owner'` by default). Management operations (invite, role
 * change, org update/delete) require the first role, or `'admin'`
 * when present in the list.
 */

type MembershipRow = {
  readonly id: string
  readonly organizationId: string
  readonly userId: string | null
  readonly invitedEmail: string | null
  readonly role: string
  readonly status: string
}

function requestUserId(req: PayloadRequest): string | null {
  const user: unknown = req.user
  if (!isRecord(user)) {
    return null
  }
  return typeof user.id === 'string' || typeof user.id === 'number' ? String(user.id) : null
}

/**
 * Payload relationship writes validate the id's runtime type against
 * the adapter (SQLite/Postgres ids are numbers, Mongo's are strings):
 * a numeric string must go back as a number or validation rejects
 * the relationship. Reads normalize to strings via `relationId`;
 * writes convert back here.
 */
function idValue(id: string): string | number {
  return /^\d+$/.test(id) ? Number(id) : id
}

function relationId(value: unknown): string | null {
  if (typeof value === 'string' || typeof value === 'number') {
    return String(value)
  }
  if (isRecord(value) && (typeof value.id === 'string' || typeof value.id === 'number')) {
    return String(value.id)
  }
  return null
}

function toMembershipRow(doc: unknown): MembershipRow | null {
  if (!isRecord(doc)) {
    return null
  }
  const id = relationId(doc.id)
  const organizationId = relationId(doc.organization)
  if (id === null || organizationId === null || typeof doc.role !== 'string') {
    return null
  }
  return {
    id,
    organizationId,
    userId: relationId(doc.user),
    invitedEmail: typeof doc.invitedEmail === 'string' ? doc.invitedEmail : null,
    role: doc.role,
    status: typeof doc.status === 'string' ? doc.status : 'active',
  }
}

async function findMemberships(
  payload: Payload,
  wired: WiredOrganizations,
  where: Where
): Promise<MembershipRow[]> {
  const result = await payload.find({
    collection: wired.membershipsCollection,
    where,
    depth: 0,
    limit: 1000,
    overrideAccess: true,
  })
  const rows: MembershipRow[] = []
  for (const doc of result.docs) {
    const row = toMembershipRow(doc)
    if (row !== null) {
      rows.push(row)
    }
  }
  return rows
}

/** The active membership roles allowed to manage an organization. */
export function orgManagerRoles(orgRoles: readonly Role[]): readonly Role[] {
  const [first] = orgRoles
  const managers: Role[] = first === undefined ? [] : [first]
  const admin = orgRoles.find((role) => role === 'admin')
  if (admin !== undefined && !managers.includes(admin)) {
    managers.push(admin)
  }
  return managers
}

/**
 * The active membership of a user in an organization, or `null`.
 * Every org authorization decision in this package reads through
 * here (invariant 5 lives in `access.ts` for collections; org role
 * checks are collection data, decided from memberships).
 */
export async function getOrgMembership(
  payload: Payload,
  wired: WiredOrganizations,
  input: { readonly userId: string; readonly organizationId: string }
): Promise<MembershipRow | null> {
  const rows = await findMemberships(payload, wired, {
    and: [
      { user: { equals: input.userId } },
      { organization: { equals: input.organizationId } },
      { status: { equals: 'active' } },
    ],
  })
  return rows[0] ?? null
}

/**
 * Whether the request's user holds one of `roles` in the given
 * organization (CAP-11 `requireOrgRole` building block for builder
 * access functions and route handlers). Fails closed on anonymous
 * requests, unknown orgs, invited (not yet accepted) memberships,
 * and storage errors are the caller's to handle — this reads live
 * membership data on every call, like the strategy reloads users.
 */
export async function requireOrgRole(
  req: PayloadRequest,
  wired: WiredOrganizations,
  input: { readonly organizationId: string; readonly roles: readonly Role[] }
): Promise<boolean> {
  const userId = requestUserId(req)
  if (userId === null) {
    return false
  }
  const membership = await getOrgMembership(req.payload, wired, {
    userId,
    organizationId: input.organizationId,
  })
  return membership !== null && input.roles.some((role) => role === membership.role)
}

async function userOrgIds(
  payload: Payload,
  wired: WiredOrganizations,
  userId: string
): Promise<string[]> {
  const rows = await findMemberships(payload, wired, {
    and: [{ user: { equals: userId } }, { status: { equals: 'active' } }],
  })
  return [...new Set(rows.map((row) => row.organizationId))]
}

function managerAccess(wired: WiredOrganizations): Access {
  const managers = orgManagerRoles(wired.orgRoles)
  return async ({ req, id, data }) => {
    const organizationId =
      typeof id === 'string' || typeof id === 'number'
        ? String(id)
        : isRecord(data)
          ? relationId(data.organization)
          : null
    if (organizationId === null) {
      return false
    }
    return requireOrgRole(req, wired, { organizationId, roles: managers })
  }
}

function organizationsCollection(wired: WiredOrganizations): CollectionConfig {
  return {
    slug: wired.organizationsCollection,
    admin: {
      useAsTitle: 'name',
      description: 'Organizations managed by payload-auth-link (CAP-11).',
    },
    access: {
      read: async ({ req }) => {
        const userId = requestUserId(req)
        if (userId === null) {
          return false
        }
        const orgIds = await userOrgIds(req.payload, wired, userId)
        if (orgIds.length === 0) {
          return false
        }
        return { id: { in: orgIds } }
      },
      create: ({ req }) => requestUserId(req) !== null && !isImpersonating(req),
      update: managerAccess(wired),
      delete: managerAccess(wired),
    },
    fields: [
      { name: 'name', type: 'text', required: true },
      { name: 'slug', type: 'text', required: true, unique: true, index: true },
      {
        name: 'verifiedDomains',
        type: 'array',
        admin: {
          description:
            'Email domains verified for this organization (CAP-15): SSO sign-ins through a provider registered for SSO-domain enforcement link only when the asserted email is on one of these domains.',
        },
        fields: [
          {
            name: 'domain',
            type: 'text',
            required: true,
            validate: (value: unknown) =>
              typeof value === 'string' && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(value)
                ? true
                : 'must be a lowercase domain like example.com',
          },
        ],
      },
    ],
    hooks: {
      afterChange: [
        async ({ doc, operation, req }) => {
          // The creator becomes the first member with the owner role
          // (first of `orgRoles`). Seeded/programmatic creates without
          // a request user skip this; managers can add members after.
          if (operation !== 'create') {
            return
          }
          const userId = req === undefined ? null : requestUserId(req)
          const organizationId = relationId(isRecord(doc) ? doc.id : null)
          const [ownerRole] = wired.orgRoles
          if (
            userId === null ||
            organizationId === null ||
            ownerRole === undefined ||
            req === undefined
          ) {
            return
          }
          const existing = await getOrgMembership(req.payload, wired, { userId, organizationId })
          if (existing === null) {
            await req.payload.create({
              collection: wired.membershipsCollection,
              data: {
                user: idValue(userId),
                organization: idValue(organizationId),
                role: ownerRole,
                status: 'active',
              },
              overrideAccess: true,
            })
          }
          // No return: the hook never modifies the organization doc.
        },
      ],
    },
  }
}

function membershipsCollection(
  wiredOpts: WiredOptions,
  wired: WiredOrganizations
): CollectionConfig {
  return {
    slug: wired.membershipsCollection,
    admin: {
      description: 'Organization memberships managed by payload-auth-link (CAP-11).',
    },
    access: {
      read: async ({ req }) => {
        const userId = requestUserId(req)
        if (userId === null) {
          return false
        }
        const orgIds = await userOrgIds(req.payload, wired, userId)
        const clauses: Where[] = [{ user: { equals: userId } }]
        if (orgIds.length > 0) {
          clauses.push({ organization: { in: orgIds } })
        }
        return { or: clauses }
      },
      // Membership writes go to org managers; the owner-bootstrap
      // hook and the invite/accept endpoints use overrideAccess
      // after their own checks.
      create: async ({ req, data }) => {
        const organizationId = isRecord(data) ? relationId(data.organization) : null
        if (organizationId === null) {
          return false
        }
        return requireOrgRole(req, wired, {
          organizationId,
          roles: orgManagerRoles(wired.orgRoles),
        })
      },
      update: async ({ req, id }) => {
        if (id === undefined) {
          return false
        }
        const doc = await req.payload
          .findByID({ collection: wired.membershipsCollection, id, depth: 0, overrideAccess: true })
          .catch(() => null)
        const row = toMembershipRow(doc)
        if (row === null) {
          return false
        }
        return requireOrgRole(req, wired, {
          organizationId: row.organizationId,
          roles: orgManagerRoles(wired.orgRoles),
        })
      },
      delete: async ({ req, id }) => {
        if (id === undefined) {
          return false
        }
        const doc = await req.payload
          .findByID({ collection: wired.membershipsCollection, id, depth: 0, overrideAccess: true })
          .catch(() => null)
        const row = toMembershipRow(doc)
        return row !== null
          ? requireOrgRole(req, wired, {
              organizationId: row.organizationId,
              roles: orgManagerRoles(wired.orgRoles),
            })
          : false
      },
    },
    fields: [
      {
        name: 'user',
        type: 'relationship',
        relationTo: wiredOpts.config.map.usersCollection,
        index: true,
      },
      { name: 'invitedEmail', type: 'email', index: true },
      {
        name: 'organization',
        type: 'relationship',
        relationTo: wired.organizationsCollection,
        required: true,
        index: true,
      },
      {
        name: 'role',
        type: 'select',
        required: true,
        options: wired.orgRoles.map((role) => ({ label: role, value: role })),
      },
      {
        name: 'status',
        type: 'select',
        required: true,
        defaultValue: 'active',
        options: [
          { label: 'invited', value: 'invited' },
          { label: 'active', value: 'active' },
        ],
      },
    ],
  }
}

/**
 * Append the organization collections when enabled. Pure config
 * transform like the users collection: collisions throw
 * {@link InvalidConfigError} instead of silently reusing a
 * builder collection with an unknown shape.
 */
export function applyOrganizationCollections(
  collections: readonly CollectionConfig[] | undefined,
  wired: WiredOptions
): CollectionConfig[] {
  const orgs = wired.organizations
  if (orgs === null) {
    return [...(collections ?? [])]
  }
  for (const slug of [orgs.organizationsCollection, orgs.membershipsCollection]) {
    if ((collections ?? []).some((collection) => collection.slug === slug)) {
      throw new InvalidConfigError(
        `organizations are enabled but a '${slug}' collection already exists; rename it or configure different organization slugs`
      )
    }
  }
  return [...(collections ?? []), organizationsCollection(orgs), membershipsCollection(wired, orgs)]
}

async function readJsonBody(req: PayloadRequest): Promise<Record<string, unknown> | null> {
  // Custom endpoints do not get a parsed body for free: Payload's
  // sanctioned `addDataAndFileToRequest` populates `req.data` (the
  // framework handler may already have done it).
  try {
    if (!isRecord(req.data)) {
      await addDataAndFileToRequest(req)
    }
    if (isRecord(req.data)) {
      return req.data
    }
    const body: unknown = await req.json?.()
    return isRecord(body) ? body : null
  } catch {
    return null
  }
}

function stringField(body: Record<string, unknown>, field: string): string | null {
  const value = body[field]
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null
}

/**
 * Organization endpoints (CAP-11). Every handler verifies the plugin
 * session explicitly (custom endpoints are unauthenticated by
 * default); every state-changing handler additionally requires CSRF
 * proof and the relevant org role — authorization is membership
 * data, checked live, never a claim from the request body.
 */
export function createOrganizationEndpoints(wired: WiredOptions): Endpoint[] {
  const orgs = wired.organizations
  if (orgs === null) {
    return []
  }
  const verifiedUser = async (req: PayloadRequest) => {
    const { users, sessions } = createServices(wired, req.payload)
    const session = await sessions.verify(req.headers)
    if (session.isErr()) {
      return null
    }
    const found = await users.findById(session.value.userId)
    return found.isOk() ? found.value : null
  }
  const csrf = (req: PayloadRequest): boolean =>
    passesCsrfForChannel(req.headers, wired.config.baseUrl, wired.admitChannels)

  return [
    {
      path: '/auth-link/organizations',
      method: 'get',
      handler: async (req) => {
        const user = await verifiedUser(req)
        if (user === null) {
          return unauthorized()
        }
        const mine = await findMemberships(req.payload, orgs, {
          and: [{ user: { equals: String(user.id) } }, { status: { equals: 'active' } }],
        })
        const organizations: {
          id: string
          name: string | null
          slug: string | null
          role: string
        }[] = []
        for (const membership of mine) {
          const doc = await req.payload
            .findByID({
              collection: orgs.organizationsCollection,
              id: membership.organizationId,
              depth: 0,
              overrideAccess: true,
            })
            .catch(() => null)
          organizations.push({
            id: membership.organizationId,
            name: isRecord(doc) && typeof doc.name === 'string' ? doc.name : null,
            slug: isRecord(doc) && typeof doc.slug === 'string' ? doc.slug : null,
            role: membership.role,
          })
        }
        const invited = await findMemberships(req.payload, orgs, {
          and: [{ invitedEmail: { equals: user.email } }, { status: { equals: 'invited' } }],
        })
        return jsonResponse(
          {
            organizations,
            invitations: invited.map((row) => ({
              id: row.id,
              organizationId: row.organizationId,
              role: row.role,
            })),
          },
          200
        )
      },
    },
    {
      path: '/auth-link/organizations',
      method: 'post',
      handler: async (req) => {
        if (!csrf(req)) {
          return forbidden('csrf check failed')
        }
        const user = await verifiedUser(req)
        if (user === null) {
          return unauthorized()
        }
        if (isImpersonating(req)) {
          return forbidden('organizations cannot be created while impersonating')
        }
        const body = await readJsonBody(req)
        const name = body === null ? null : stringField(body, 'name')
        const slug = body === null ? null : stringField(body, 'slug')
        if (name === null || slug === null || !/^[a-z0-9][a-z0-9-]*$/.test(slug)) {
          return jsonResponse({ error: 'name and a lowercase slug are required' }, 400)
        }
        try {
          const created = await req.payload.create({
            collection: orgs.organizationsCollection,
            data: { name, slug },
            // The collection hook reads the creator from the request
            // to seed the owner membership; pass the request through.
            req,
            overrideAccess: true,
          })
          // Ensure the owner membership even when Payload auth did not
          // populate `req.user` for this custom endpoint (the session
          // was verified explicitly above either way).
          const [ownerRole] = orgs.orgRoles
          const seeded = await getOrgMembership(req.payload, orgs, {
            userId: String(user.id),
            organizationId: String(created.id),
          })
          if (seeded === null && ownerRole !== undefined) {
            await req.payload.create({
              collection: orgs.membershipsCollection,
              data: {
                user: idValue(String(user.id)),
                organization: idValue(String(created.id)),
                role: ownerRole,
                status: 'active',
              },
              overrideAccess: true,
            })
          }
          return jsonResponse({ organization: { id: String(created.id), name, slug } }, 201)
        } catch (cause) {
          wired.logger.warn('organization create failed', { cause })
          return jsonResponse({ error: 'organization could not be created' }, 400)
        }
      },
    },
    {
      path: '/auth-link/organizations/invite',
      method: 'post',
      handler: async (req) => {
        if (!csrf(req)) {
          return forbidden('csrf check failed')
        }
        const user = await verifiedUser(req)
        if (user === null) {
          return unauthorized()
        }
        const body = await readJsonBody(req)
        const organizationId = body === null ? null : stringField(body, 'organizationId')
        const rawEmail = body === null ? null : stringField(body, 'email')
        const rawRole = body === null ? null : stringField(body, 'role')
        const email = rawEmail === null ? null : parseEmail(rawEmail)
        const role: Role | null =
          rawRole === null
            ? (orgs.orgRoles.at(-1) ?? null)
            : (() => {
                const parsed = parseRole(rawRole)
                return parsed.isOk() && orgs.orgRoles.includes(parsed.value) ? parsed.value : null
              })()
        if (organizationId === null || email === null || email.isErr() || role === null) {
          return jsonResponse(
            { error: 'organizationId, a valid email, and a known role are required' },
            400
          )
        }
        const caller = await getOrgMembership(req.payload, orgs, {
          userId: String(user.id),
          organizationId,
        })
        const allowed =
          caller !== null && orgManagerRoles(orgs.orgRoles).some((role) => role === caller.role)
        if (!allowed) {
          return forbidden('organization managers only')
        }
        // An existing Payload user with that email becomes a member
        // immediately; otherwise the invitation waits for acceptance
        // after they sign in with that address.
        const { users } = createServices(wired, req.payload)
        const existing = await users.findByEmail(email.value)
        if (existing.isErr()) {
          return jsonResponse({ error: 'invitation could not be created' }, 500)
        }
        // One membership per user per org: a second invite must not
        // create a competing row (role resolution reads the first
        // match, so duplicates would make the effective role
        // nondeterministic). Pending invites for the same address
        // deduplicate the same way.
        if (existing.value !== null) {
          const already = await getOrgMembership(req.payload, orgs, {
            userId: String(existing.value.id),
            organizationId,
          })
          if (already !== null) {
            return jsonResponse({ error: 'user is already a member' }, 409)
          }
        }
        const pending = await findMemberships(req.payload, orgs, {
          and: [
            { organization: { equals: idValue(organizationId) } },
            { invitedEmail: { equals: email.value } },
            { status: { equals: 'invited' } },
          ],
        })
        if (pending.length > 0) {
          return jsonResponse({ error: 'an invitation for this email is already pending' }, 409)
        }
        const created = await req.payload.create({
          collection: orgs.membershipsCollection,
          data: {
            organization: idValue(organizationId),
            role,
            ...(existing.value === null
              ? { invitedEmail: email.value, status: 'invited' }
              : { user: idValue(String(existing.value.id)), status: 'active' }),
          },
          overrideAccess: true,
        })
        return jsonResponse(
          {
            invitation: {
              id: String(created.id),
              organizationId,
              role,
              status: existing.value === null ? 'invited' : 'active',
            },
          },
          201
        )
      },
    },
    {
      path: '/auth-link/organizations/accept',
      method: 'post',
      handler: async (req) => {
        if (!csrf(req)) {
          return forbidden('csrf check failed')
        }
        const user = await verifiedUser(req)
        if (user === null) {
          return unauthorized()
        }
        const body = await readJsonBody(req)
        const invitationId = body === null ? null : stringField(body, 'invitationId')
        if (invitationId === null) {
          return jsonResponse({ error: 'invitationId is required' }, 400)
        }
        const doc = await req.payload
          .findByID({
            collection: orgs.membershipsCollection,
            id: invitationId,
            depth: 0,
            overrideAccess: true,
          })
          .catch(() => null)
        const row = toMembershipRow(doc)
        // Only the invited email may accept, and only once: the
        // address on the verified Payload user is the authority,
        // never a value from the request body.
        if (row === null || row.status !== 'invited' || row.invitedEmail !== user.email) {
          return forbidden('invitation is not yours to accept')
        }
        await req.payload.update({
          collection: orgs.membershipsCollection,
          id: invitationId,
          data: { user: idValue(String(user.id)), status: 'active', invitedEmail: null },
          overrideAccess: true,
        })
        return jsonResponse(
          { membership: { id: invitationId, organizationId: row.organizationId, role: row.role } },
          200
        )
      },
    },
  ]
}
