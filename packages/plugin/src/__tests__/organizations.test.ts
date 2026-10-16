/**
 * Organization collections and helpers, unit level (issue #86): the
 * defensive paths the SQLite integration suites cannot produce —
 * Mongo-style string ids, populated relationships, malformed stored
 * rows, hooks invoked without a request or request context, and
 * access functions called without an id or data. Each case drives
 * the real collection config `applyOrganizationCollections` returns,
 * against a fake `payload` that records what it was asked.
 */
import { InvalidConfigError, InvalidRoleError } from '@payload-auth-link/core'
import type {
  Access,
  CollectionAfterChangeHook,
  CollectionAfterDeleteHook,
  CollectionBeforeChangeHook,
  CollectionBeforeDeleteHook,
  CollectionConfig,
  PayloadRequest,
} from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { wireOptions } from '../options.js'
import { applyOrganizationCollections, orgManagerRoles, requireOrgRole } from '../organizations.js'
import { createStubProvider } from './stub-provider.js'

function wired(organizations = true) {
  return wireOptions({
    baseUrl: 'http://orgs-unit.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [createStubProvider().provider],
    ...(organizations ? { organizations: { enabled: true } } : {}),
  })
}

const wiring = { organizationsCollection: 'organizations', membershipsCollection: 'memberships' }

type FakePayload = {
  find: ReturnType<typeof vi.fn>
  findByID: ReturnType<typeof vi.fn>
  create: ReturnType<typeof vi.fn>
  delete: ReturnType<typeof vi.fn>
  db: { updateOne: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn> }
}

function fakePayload(opts: { docs?: unknown[]; byId?: unknown } = {}): FakePayload {
  return {
    find: vi.fn(() => Promise.resolve({ docs: opts.docs ?? [] })),
    findByID: vi.fn(() => Promise.resolve(opts.byId ?? null)),
    create: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({ docs: [], errors: [] })),
    db: { updateOne: vi.fn(() => Promise.resolve(null)), create: vi.fn(() => Promise.resolve({})) },
  }
}

function request(payload: FakePayload, extra: Record<string, unknown> = {}): PayloadRequest {
  return { user: { id: 'u1' }, payload, context: {}, ...extra } as unknown as PayloadRequest
}

function collections(): { orgs: CollectionConfig; memberships: CollectionConfig } {
  const [orgs, memberships] = applyOrganizationCollections(undefined, wired())
  if (orgs === undefined || memberships === undefined) {
    throw new Error('organization collections missing')
  }
  return { orgs, memberships }
}

function access(collection: CollectionConfig, op: 'create' | 'update' | 'delete'): Access {
  const fn = collection.access?.[op]
  if (fn === undefined) {
    throw new Error(`access.${op} missing`)
  }
  return fn
}

function callAccess(fn: Access, args: Record<string, unknown>): Promise<unknown> {
  return Promise.resolve(fn(args as unknown as Parameters<Access>[0]))
}

async function statusOf(promise: Promise<unknown>): Promise<number | undefined> {
  try {
    await promise
    return undefined
  } catch (error) {
    return (error as { status?: number }).status
  }
}

describe('applyOrganizationCollections', () => {
  it('passes collections through untouched when organizations are disabled', () => {
    expect(applyOrganizationCollections(undefined, wired(false))).toEqual([])
    const users: CollectionConfig = { slug: 'users', fields: [] }
    expect(applyOrganizationCollections([users], wired(false))).toEqual([users])
  })

  it('appends both collections when none exist yet', () => {
    expect(applyOrganizationCollections(undefined, wired()).map((c) => c.slug)).toEqual([
      'organizations',
      'memberships',
    ])
  })

  it('refuses to shadow a builder collection with the same slug', () => {
    for (const slug of ['organizations', 'memberships']) {
      expect(() => applyOrganizationCollections([{ slug, fields: [] }], wired())).toThrow(
        InvalidConfigError
      )
    }
  })
})

describe('orgManagerRoles', () => {
  it('is empty for an empty role list and never duplicates a leading admin', () => {
    expect(orgManagerRoles([])).toEqual([])
    expect(orgManagerRoles(wired().organizations?.orgRoles ?? [])).toEqual(['owner', 'admin'])
    const adminFirst = wireOptions({
      baseUrl: 'http://orgs-unit.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [createStubProvider().provider],
      organizations: { enabled: true, orgRoles: ['admin', 'member'] },
    }).organizations
    expect(orgManagerRoles(adminFirst?.orgRoles ?? [])).toEqual(['admin'])
  })
})

describe('requireOrgRole', () => {
  it('throws on a malformed role instead of matching nothing', async () => {
    const payload = fakePayload()
    await expect(
      requireOrgRole(request(payload), wiring, { organizationId: 'o1', roles: ['NOT A ROLE!'] })
    ).rejects.toBeInstanceOf(InvalidRoleError)
  })

  it('fails closed when req.user carries no usable id', async () => {
    const payload = fakePayload({
      docs: [{ id: 'm1', organization: 'o1', user: 'u1', role: 'owner', status: 'active' }],
    })
    for (const user of [{ id: { nested: 1 } }, { id: null }, 'u1']) {
      expect(
        await requireOrgRole(request(payload, { user }), wiring, {
          organizationId: 'o1',
          roles: ['owner'],
        })
      ).toBe(false)
    }
    expect(payload.find).not.toHaveBeenCalled()
  })

  it('skips malformed stored rows and reads populated relationships', async () => {
    const payload = fakePayload({
      docs: [
        'not a row',
        { id: { id: null }, organization: 'o1', role: 'owner' },
        { id: 'm1', organization: { id: { deep: true } }, role: 'owner' },
        { id: 'm2', organization: 'o1', role: 7 },
        // Populated relationships (depth > 0 / Mongo ids) and a row
        // without a stored status (treated as active).
        { id: { id: 3 }, organization: { id: 'o1' }, user: { id: 7 }, role: 'member' },
      ],
    })
    expect(
      await requireOrgRole(request(payload), wiring, { organizationId: 'o1', roles: ['member'] })
    ).toBe(true)
    expect(
      await requireOrgRole(request(payload), wiring, { organizationId: 'o1', roles: ['owner'] })
    ).toBe(false)
  })
})

describe('organization access', () => {
  it('bulk update/delete (no id) are scoped to the organizations the caller manages', async () => {
    const { orgs } = collections()
    const rows = [
      { id: 'm1', organization: 'org-abc', user: 'u1', role: 'owner', status: 'active' },
      { id: 'm2', organization: { id: 'org-def' }, user: 'u1', role: 'admin', status: 'active' },
      { id: 'm3', organization: 'org-abc', user: 'u1', role: 'admin', status: 'active' },
    ]
    const managerRoles = { update: '["owner","admin"]', delete: '["owner"]' }
    for (const op of ['update', 'delete'] as const) {
      const payload = fakePayload({ docs: rows })
      // A body naming some organization is never the authority.
      const scoped = await callAccess(access(orgs, op), {
        req: request(payload),
        data: { organization: 'org-victim' },
      })
      expect(scoped).toEqual({ id: { in: ['org-abc', 'org-def'] } })
      // Only the caller's active rows with a qualifying role are
      // consulted: managers may update, only owners may delete.
      const [findArgs] = payload.find.mock.calls[0] as [{ where: unknown }]
      expect(JSON.stringify(findArgs.where)).toContain(`"in":${managerRoles[op]}`)
    }
  })

  it('bulk update/delete refuse callers who manage nothing, or have no user', async () => {
    const { orgs } = collections()
    for (const op of ['update', 'delete'] as const) {
      const none = fakePayload()
      expect(await callAccess(access(orgs, op), { req: request(none) })).toBe(false)
      const anonymous = fakePayload()
      expect(await callAccess(access(orgs, op), { req: request(anonymous, { user: null }) })).toBe(
        false
      )
      expect(anonymous.find).not.toHaveBeenCalled()
    }
  })
})

describe('membership access', () => {
  it('create refuses missing or non-object data', async () => {
    const { memberships } = collections()
    const payload = fakePayload()
    for (const data of [undefined, null, 'owner', { organization: 'o1' }, { role: 'member' }]) {
      expect(await callAccess(access(memberships, 'create'), { req: request(payload), data })).toBe(
        false
      )
    }
    expect(payload.find).not.toHaveBeenCalled()
  })

  it('update/delete refuse when Payload passes no id', async () => {
    const { memberships } = collections()
    const payload = fakePayload()
    for (const op of ['update', 'delete'] as const) {
      expect(await callAccess(access(memberships, op), { req: request(payload) })).toBe(false)
    }
    expect(payload.findByID).not.toHaveBeenCalled()
  })

  it('update refuses a stored row that is malformed', async () => {
    const { memberships } = collections()
    const payload = fakePayload({ byId: { id: 'm1', role: 'member' } })
    expect(
      await callAccess(access(memberships, 'update'), {
        req: request(payload),
        id: 'm1',
        data: { role: 'member' },
      })
    ).toBe(false)
  })
})

describe('membership integrity hook', () => {
  function hook(): CollectionBeforeChangeHook {
    const fn = collections().memberships.hooks?.beforeChange?.[0]
    if (fn === undefined) {
      throw new Error('beforeChange missing')
    }
    return fn
  }

  function run(args: Record<string, unknown>): Promise<unknown> {
    return Promise.resolve(hook()(args as unknown as Parameters<CollectionBeforeChangeHook>[0]))
  }

  it('rejects an update whose stored row is malformed (400)', async () => {
    const payload = fakePayload()
    expect(
      await statusOf(
        run({
          operation: 'update',
          data: { role: 'member' },
          originalDoc: {},
          req: request(payload),
        })
      )
    ).toBe(400)
    expect(
      await statusOf(
        run({ operation: 'update', data: {}, originalDoc: undefined, req: request(payload) })
      )
    ).toBe(400)
  })

  it('keeps the stored role and status when the write omits them', async () => {
    const payload = fakePayload()
    const data = { invitedEmail: 'x@unit.test' }
    const member = {
      id: 'm1',
      organization: 'org-abc',
      user: 'u1',
      role: 'member',
      status: 'active',
    }
    expect(
      await run({ operation: 'update', data, originalDoc: member, req: request(payload) })
    ).toBe(data)
    // A member row never consults the owner count.
    expect(payload.find).not.toHaveBeenCalled()
  })

  it('guards the last owner with string (Mongo-style) organization ids', async () => {
    const owner = { id: 'm1', organization: 'org-abc', user: 'u1', role: 'owner', status: 'active' }
    const payload = fakePayload({ docs: [owner] })
    expect(
      await statusOf(
        run({
          operation: 'update',
          data: { status: 'invited' },
          originalDoc: owner,
          req: request(payload),
        })
      )
    ).toBe(409)
    const [findArgs] = payload.find.mock.calls[0] as [{ where: unknown }]
    expect(JSON.stringify(findArgs.where)).toContain('"equals":"org-abc"')
    // The organization row is written (locked) before owners are counted.
    expect(payload.db.updateOne).toHaveBeenCalledWith(
      expect.objectContaining({ collection: 'organizations', id: 'org-abc' })
    )
  })
})

describe('membership delete guard', () => {
  it('works without a request context and lets a non-last owner go', async () => {
    const fn = collections().memberships.hooks?.beforeDelete?.[0]
    if (fn === undefined) {
      throw new Error('beforeDelete missing')
    }
    const owner = { id: 'm1', organization: 'o1', user: 'u1', role: 'owner', status: 'active' }
    const other = { id: 'm2', organization: 'o1', user: 'u2', role: 'owner', status: 'active' }
    const payload = fakePayload({ byId: owner, docs: [owner, other] })
    const req = request(payload, { context: undefined })
    await expect(
      Promise.resolve(fn({ id: 'm1', req } as unknown as Parameters<CollectionBeforeDeleteHook>[0]))
    ).resolves.toBeUndefined()
    const lonely = fakePayload({ byId: owner, docs: [owner] })
    expect(
      await statusOf(
        Promise.resolve(
          fn({
            id: 'm1',
            req: request(lonely, { context: 'not a record' }),
          } as unknown as Parameters<CollectionBeforeDeleteHook>[0])
        )
      )
    ).toBe(409)
  })
})

describe('organization hooks', () => {
  it('the cascade initialises a missing request context and keeps string ids', async () => {
    const fn = collections().orgs.hooks?.beforeDelete?.[0]
    if (fn === undefined) {
      throw new Error('beforeDelete missing')
    }
    const payload = fakePayload()
    const req = request(payload, { context: undefined })
    await fn({ id: 'org-abc', req } as unknown as Parameters<CollectionBeforeDeleteHook>[0])
    expect(payload.delete).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'memberships',
        where: { organization: { equals: 'org-abc' } },
      })
    )
    // The in-flight marker is cleared once the cascade finished.
    const context = req.context as Record<string, unknown>
    const deleting = context['payload-auth-link:deleting-organizations']
    expect(deleting).toBeInstanceOf(Set)
    expect((deleting as Set<string>).size).toBe(0)
  })

  function afterChange(): CollectionAfterChangeHook {
    const fn = collections().orgs.hooks?.afterChange?.[0]
    if (fn === undefined) {
      throw new Error('afterChange missing')
    }
    return fn
  }

  function runAfterChange(args: Record<string, unknown>): Promise<unknown> {
    return Promise.resolve(
      afterChange()(args as unknown as Parameters<CollectionAfterChangeHook>[0])
    )
  }

  it('owner seeding skips requests without a user, a request, or a doc id', async () => {
    const payload = fakePayload()
    await runAfterChange({ operation: 'create', doc: { id: 'o1' }, req: undefined })
    await runAfterChange({ operation: 'create', doc: 'not a doc', req: request(payload) })
    await runAfterChange({
      operation: 'create',
      doc: { id: 'o1' },
      req: request(payload, { user: null }),
    })
    expect(payload.find).not.toHaveBeenCalled()
    expect(payload.create).not.toHaveBeenCalled()
  })

  it('owner seeding never duplicates an existing membership', async () => {
    const existing = { id: 'm1', organization: 'o1', user: 'u1', role: 'owner', status: 'active' }
    const payload = fakePayload({ docs: [existing] })
    await runAfterChange({ operation: 'create', doc: { id: 'o1' }, req: request(payload) })
    expect(payload.find).toHaveBeenCalledTimes(1)
    expect(payload.create).not.toHaveBeenCalled()
  })
})

describe('last-owner post-write re-check', () => {
  function hooks() {
    const { memberships } = collections()
    const afterDelete = memberships.hooks?.afterDelete?.[0]
    const afterChange = memberships.hooks?.afterChange?.[0]
    if (afterDelete === undefined || afterChange === undefined) {
      throw new Error('membership after-hooks missing')
    }
    return {
      afterDelete: (args: Record<string, unknown>) =>
        Promise.resolve(afterDelete(args as unknown as Parameters<CollectionAfterDeleteHook>[0])),
      afterChange: (args: Record<string, unknown>) =>
        Promise.resolve(afterChange(args as unknown as Parameters<CollectionAfterChangeHook>[0])),
    }
  }

  it('restores a removed owner row (user-less rows included) and refuses with 409', async () => {
    const payload = fakePayload({ docs: [] })
    const doc = { id: 'm9', organization: 'org-abc', user: null, role: 'owner', status: 'active' }
    expect(await statusOf(hooks().afterDelete({ doc, req: request(payload) }))).toBe(409)
    expect(payload.db.create).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'memberships',
        data: { id: 'm9', organization: 'org-abc', role: 'owner', status: 'active' },
      })
    )
  })

  it('restores a demoted last owner and refuses with 409', async () => {
    const payload = fakePayload({ docs: [] })
    const previousDoc = {
      id: 'm1',
      organization: 'o1',
      user: 'u1',
      role: 'owner',
      status: 'active',
    }
    const doc = { ...previousDoc, role: 'member' }
    expect(
      await statusOf(
        hooks().afterChange({ operation: 'update', doc, previousDoc, req: request(payload) })
      )
    ).toBe(409)
    expect(payload.db.updateOne).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'm1', data: { role: 'owner', status: 'active' } })
    )
  })

  it('leaves the write alone while another owner remains, or for non-owner rows', async () => {
    const other = { id: 'm2', organization: 'o1', user: 'u2', role: 'owner', status: 'active' }
    const payload = fakePayload({ docs: [other] })
    const owner = { id: 'm1', organization: 'o1', user: 'u1', role: 'owner', status: 'active' }
    await hooks().afterDelete({ doc: owner, req: request(payload) })
    await hooks().afterChange({
      operation: 'update',
      doc: { ...owner, role: 'admin' },
      previousDoc: owner,
      req: request(payload),
    })
    await hooks().afterDelete({ doc: { ...owner, role: 'member' }, req: request(payload) })
    await hooks().afterChange({ operation: 'create', doc: owner, req: request(payload) })
    expect(payload.db.create).not.toHaveBeenCalled()
    expect(payload.db.updateOne).not.toHaveBeenCalled()
  })
})
