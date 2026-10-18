/**
 * The raw Payload database adapter, driven WITHOUT Better Auth's
 * adapter factory in front of it (issue #113). The factory normalizes
 * inputs before they reach the adapter — it answers an empty-where
 * `update` with `null` on its own, for example — so the engine suites
 * can never reach the adapter's own guards. Here `createAdapterFactory`
 * is mocked to hand back the adapter creator, which runs against a
 * scripted Payload Local API:
 *
 * - schema validation refuses every unmapped rename / field / model;
 * - malformed Payload results surface as `AdapterOperationError`,
 *   never as half-formed rows;
 * - an empty-where `update` touches nothing (without the guard, the
 *   translated empty where would update the FIRST row of the model);
 * - joins, adopted-model host validation and id coercion.
 */
import { getAuthTables } from 'better-auth/db'
import type { CleanedWhere, CustomAdapter, JoinConfig } from 'better-auth/adapters'
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { createPayloadDatabaseAdapter, type PayloadDatabaseAdapterDeps } from '../adapter.js'
import { AdapterOperationError, UnknownModelError, UnsupportedSchemaError } from '../errors.js'

vi.mock('better-auth/adapters', async (importOriginal) => {
  const actual = await importOriginal<typeof import('better-auth/adapters')>()
  // Hand the adapter config back instead of wrapping it in the factory.
  return { ...actual, createAdapterFactory: (config: unknown) => config }
})

type Schema = Record<string, { fields: Record<string, { type: unknown }> }>
type RawFactory = { adapter: (ctx: unknown) => CustomAdapter }
type Call = (args: Record<string, unknown>) => Promise<unknown>

function coreSchema(): Schema {
  return getAuthTables({})
}

function creatorContext(
  schema: Schema,
  rename: { model?: Record<string, string>; field?: Record<string, string> } = {}
): unknown {
  return {
    schema,
    getModelName: (model: string) => rename.model?.[model] ?? model,
    getFieldName: ({ model, field }: { model: string; field: string }) =>
      rename.field?.[`${model}.${field}`] ?? field,
  }
}

function fakePayload(
  calls: Partial<Record<'find' | 'create' | 'update' | 'delete' | 'count', Call>> = {},
  collections: Record<string, unknown> = {}
) {
  const empty: Call = () => Promise.resolve({ docs: [], errors: [], hasNextPage: false })
  const mocks = {
    find: vi.fn(calls.find ?? empty),
    create: vi.fn(calls.create ?? empty),
    update: vi.fn(calls.update ?? empty),
    delete: vi.fn(calls.delete ?? empty),
    count: vi.fn(calls.count ?? (() => Promise.resolve({ totalDocs: 0 }))),
  }
  return { mocks, payload: { ...mocks, collections } as unknown as Payload }
}

function rawAdapter(
  payload: Payload,
  deps: Omit<PayloadDatabaseAdapterDeps, 'getPayload'> = {},
  ctx: unknown = creatorContext(coreSchema())
): CustomAdapter {
  const factory = createPayloadDatabaseAdapter({
    ...deps,
    getPayload: () => Promise.resolve(payload),
  }) as unknown as RawFactory
  return factory.adapter(ctx)
}

function eq(field: string, value: CleanedWhere['value']): CleanedWhere {
  return { field, value, operator: 'eq', connector: 'AND', mode: 'sensitive' }
}

const userDoc = { id: 1, baId: 'u1', email: 'a@example.com', name: 'A', emailVerified: false }

describe('schema validation at adapter creation', () => {
  const { payload } = fakePayload()

  it('refuses a missing core table, but tolerates a missing rateLimit table', () => {
    const schema = coreSchema()
    delete schema.rateLimit
    expect(() => rawAdapter(payload, {}, creatorContext(schema))).not.toThrow()
    delete schema.session
    expect(() => rawAdapter(payload, {}, creatorContext(schema))).toThrow(
      /missing table for model "session"/
    )
  })

  it('refuses renamed models and renamed core fields', () => {
    expect(() =>
      rawAdapter(payload, {}, creatorContext(coreSchema(), { model: { user: 'people' } }))
    ).toThrow(/model "user" is renamed to "people"/)
    expect(() =>
      rawAdapter(payload, {}, creatorContext(coreSchema(), { field: { 'user.email': 'mail' } }))
    ).toThrow(/field "user.email" is renamed to "mail"/)
  })

  it('refuses undeclared fields and declared-but-absent fields', () => {
    const schema = coreSchema()
    const user = schema.user
    if (user === undefined) {
      throw new Error('no user table')
    }
    user.fields.nickname = { type: 'string' }
    expect(() => rawAdapter(payload, {}, creatorContext(schema))).toThrow(
      /field "user.nickname" has no Payload column/
    )
    expect(() =>
      rawAdapter(payload, { customFields: { user: [{ name: 'nickname', type: 'text' }] } })
    ).toThrow(/declared field "user.nickname" is missing from the Better Auth schema/)
  })

  it('refuses custom models that are missing, renamed, or undeclared', () => {
    const custom = {
      customModels: [{ model: 'widget', fields: [{ name: 'label', type: 'text' as const }] }],
    }
    expect(() => rawAdapter(payload, custom)).toThrow(/missing table for custom model "widget"/)
    const schema: Schema = { ...coreSchema(), widget: { fields: { label: { type: 'string' } } } }
    expect(() =>
      rawAdapter(payload, custom, creatorContext(schema, { model: { widget: 'gadgets' } }))
    ).toThrow(/model "widget" is renamed to "gadgets"/)
    expect(() => rawAdapter(payload, {}, creatorContext(schema))).toThrow(
      /model "widget" is not declared/
    )
    expect(() => rawAdapter(payload, custom, creatorContext(schema))).not.toThrow()
  })
})

describe('malformed Payload results are adapter errors', () => {
  it('an unknown model is refused before any query', async () => {
    const { payload, mocks } = fakePayload()
    await expect(rawAdapter(payload).findOne({ model: 'nope', where: [] })).rejects.toBeInstanceOf(
      UnknownModelError
    )
    expect(mocks.find).not.toHaveBeenCalled()
  })

  it.each([
    ['a non-object result', 'oops', /expected a result with a docs array/],
    ['docs that are not documents', { docs: ['row'] }, /expected a document, received string/],
    ['a row without its baId', { docs: [{ id: 1, email: 'a@example.com' }] }, /missing baId/],
    [
      'an unparseable date',
      { docs: [{ ...userDoc, createdAt: 'not-a-date' }] },
      /createdAt is not a valid date/,
    ],
  ])('findOne with %s', async (_label, result, message) => {
    const { payload } = fakePayload({ find: () => Promise.resolve(result) })
    const failure = rawAdapter(payload).findOne({ model: 'user', where: [eq('id', 'u1')] })
    await expect(failure).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(failure).rejects.toThrow(message)
  })

  it('a non-record create input and a non-record created doc', async () => {
    const { payload } = fakePayload({ create: () => Promise.resolve(null) })
    const adapter = rawAdapter(payload)
    await expect(
      adapter.create({ model: 'user', data: 'text' as unknown as Record<string, unknown> })
    ).rejects.toThrow(/write: expected a data object/)
    await expect(adapter.create({ model: 'user', data: { id: 'u9' } })).rejects.toThrow(
      /create user: expected a document, received object/
    )
  })

  it('a count without totalDocs, a paged read without hasNextPage', async () => {
    const { payload } = fakePayload({
      count: () => Promise.resolve({ total: 3 }),
      find: () => Promise.resolve({ docs: [] }),
    })
    const adapter = rawAdapter(payload)
    await expect(adapter.count({ model: 'user', where: [eq('id', 'u1')] })).rejects.toThrow(
      /expected a count result with totalDocs/
    )
    const insensitive = [{ ...eq('email', 'A@example.com'), mode: 'insensitive' as const }]
    await expect(adapter.count({ model: 'user', where: insensitive })).rejects.toThrow(
      /count user: expected a paginated result/
    )
    await expect(
      adapter.updateMany({ model: 'user', where: insensitive, update: { name: 'x' } })
    ).rejects.toThrow(/exact match user: expected a paginated result/)
  })

  it('a bulk result without docs/errors and a malformed error entry', async () => {
    const results: unknown[] = [{ docs: [] }, { docs: [], errors: ['locked'] }]
    const { payload } = fakePayload({ delete: () => Promise.resolve(results.shift()) })
    const adapter = rawAdapter(payload)
    await expect(adapter.deleteMany({ model: 'user', where: [eq('name', 'A')] })).rejects.toThrow(
      /expected a bulk result with docs and errors/
    )
    await expect(adapter.deleteMany({ model: 'user', where: [eq('name', 'A')] })).rejects.toThrow(
      /malformed bulk error entry/
    )
  })

  it('a document without a Payload id cannot be updated or deleted', async () => {
    const { payload, mocks } = fakePayload({
      find: () => Promise.resolve({ docs: [{ baId: 'u1', email: 'a@example.com' }] }),
    })
    const adapter = rawAdapter(payload)
    await expect(
      adapter.update({ model: 'user', where: [eq('id', 'u1')], update: { name: 'B' } })
    ).rejects.toThrow(/update user: missing Payload document id/)
    await expect(adapter.delete({ model: 'user', where: [eq('id', 'u1')] })).rejects.toThrow(
      /delete user: missing Payload document id/
    )
    expect(mocks.update).not.toHaveBeenCalled()
    expect(mocks.delete).not.toHaveBeenCalled()
  })

  it('a Payload failure is wrapped with its cause', async () => {
    const cause = new Error('db down')
    const { payload } = fakePayload({ find: () => Promise.reject(cause) })
    const failure = await rawAdapter(payload)
      .findMany({ model: 'user', where: [], limit: 1 })
      .then(
        () => null,
        (error: unknown) => error
      )
    expect(failure).toBeInstanceOf(AdapterOperationError)
    expect((failure as Error).cause).toBe(cause)
  })
})

describe('update with an empty where (issue #113)', () => {
  it('touches nothing; a scoped update writes exactly the one matched row', async () => {
    const { payload, mocks } = fakePayload({
      find: () => Promise.resolve({ docs: [userDoc] }),
      update: (args) => Promise.resolve({ ...userDoc, ...(args.data as object) }),
    })
    const adapter = rawAdapter(payload)
    // Without the guard the translated empty where matches every row and
    // the first one would be rewritten.
    expect(await adapter.update({ model: 'user', where: [], update: { name: 'all' } })).toBeNull()
    expect(mocks.find).not.toHaveBeenCalled()
    expect(mocks.update).not.toHaveBeenCalled()
    expect(await adapter.updateMany({ model: 'user', where: [], update: { name: 'all' } })).toBe(0)
    expect(mocks.update).not.toHaveBeenCalled()

    const updated = await adapter.update<Record<string, unknown>>({
      model: 'user',
      where: [eq('id', 'u1')],
      update: { name: 'B', updatedAt: new Date() },
    })
    expect(updated).toMatchObject({ id: 'u1', name: 'B' })
    expect(mocks.update).toHaveBeenCalledTimes(1)
    expect(mocks.update.mock.calls[0]?.[0]).toMatchObject({
      collection: 'ba-users',
      id: 1,
      data: { name: 'B' },
    })
  })
})

describe('joins (memory-adapter shape)', () => {
  const sessions = [
    { id: 10, baId: 's1', userId: 'u1', token: 't1', expiresAt: '2030-01-01T00:00:00.000Z' },
    { id: 11, baId: 's2', userId: 'u1', token: 't2', expiresAt: '2030-01-01T00:00:00.000Z' },
  ]
  function joinPayload() {
    return fakePayload({
      find: (args) =>
        Promise.resolve(
          args.collection === 'ba-sessions'
            ? { docs: sessions }
            : { docs: [userDoc], hasNextPage: false, totalDocs: 1 }
        ),
    })
  }

  it('one-to-many nests an array, one-to-one a single row or null', async () => {
    const { payload, mocks } = joinPayload()
    const adapter = rawAdapter(payload)
    const many: JoinConfig = {
      session: { on: { from: 'id', to: 'userId' }, relation: 'one-to-many' },
    }
    const row = await adapter.findOne<Record<string, unknown>>({
      model: 'user',
      where: [eq('id', 'u1')],
      join: many,
    })
    expect((row?.session as { id: string }[]).map((s) => s.id)).toEqual(['s1', 's2'])
    expect((row?.session as { expiresAt: unknown }[])[0]?.expiresAt).toBeInstanceOf(Date)
    expect(mocks.find).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'ba-sessions',
        where: { userId: { equals: 'u1' } },
        limit: 100,
      })
    )
    const one: JoinConfig = {
      session: { on: { from: 'id', to: 'userId' }, relation: 'one-to-one', limit: 1 },
    }
    const rows = await adapter.findMany<Record<string, unknown>>({
      model: 'user',
      where: [],
      limit: 5,
      join: one,
    })
    expect((rows[0]?.session as { id: string }).id).toBe('s1')
    const noJoin = await adapter.findMany({ model: 'user', where: [], limit: 5, join: {} })
    expect(noJoin).toHaveLength(1)
  })

  it('joins on the post-filtered (insensitive) paths too; an empty join is null', async () => {
    const { payload } = fakePayload({
      find: (args) =>
        Promise.resolve(
          args.collection === 'ba-sessions'
            ? { docs: [] }
            : { docs: [userDoc], hasNextPage: false, totalDocs: 1 }
        ),
    })
    const adapter = rawAdapter(payload)
    const one: JoinConfig = {
      session: { on: { from: 'id', to: 'userId' }, relation: 'one-to-one' },
    }
    const insensitive = [{ ...eq('email', 'A@EXAMPLE.com'), mode: 'insensitive' as const }]
    const row = await adapter.findOne<Record<string, unknown>>({
      model: 'user',
      where: insensitive,
      join: one,
    })
    expect(row?.session).toBeNull()
    const rows = await adapter.findMany<Record<string, unknown>>({
      model: 'user',
      where: insensitive,
      limit: 5,
      join: one,
    })
    expect(rows[0]?.session).toBeNull()
  })

  it('select keeps only the selected fields', async () => {
    const { payload } = joinPayload()
    const row = await rawAdapter(payload).findOne({
      model: 'user',
      where: [eq('id', 'u1')],
      select: ['email'],
    })
    expect(row).toEqual({ email: 'a@example.com' })
  })
})

describe('adopted models: host validation on first use (issue #49)', () => {
  const hostUsers = {
    config: {
      auth: { disableLocalStrategy: false },
      fields: [
        { name: 'email', type: 'email' },
        { name: 'emailVerified', type: 'checkbox' },
        { name: 'name', type: 'text' },
        { name: 'image', type: 'text' },
        { name: 'createdAt', type: 'date' },
        { name: 'updatedAt', type: 'date' },
        { type: 'ui', name: 'banner' },
        { type: 'row' },
        { name: 'layout', type: 'tabs', tabs: [{ name: 'extra', type: 'text' }] },
      ],
    },
  }

  it('injects an unknowable password into creates on a local-strategy auth collection', async () => {
    const { payload, mocks } = fakePayload(
      { create: (args) => Promise.resolve({ id: 7, ...(args.data as object) }) },
      { users: hostUsers }
    )
    const adapter = rawAdapter(payload, {
      schemaMap: { user: { slug: 'users' } },
      idStrategy: 'payload',
    })
    const created = await adapter.create<Record<string, unknown>>({
      model: 'user',
      data: { id: 'ignored', email: 'n@example.com', name: 'N', emailVerified: false },
    })
    expect(created.id).toBe('7')
    const data = mocks.create.mock.calls[0]?.[0]?.data as Record<string, unknown>
    expect(typeof data.password).toBe('string')
    expect(data.id).toBeUndefined()
    expect(data.baId).toBeUndefined()
  })

  it('fails fast when the host collection or a field is missing', async () => {
    /** The schema error behind the operation error the create reports. */
    const schemaFailure = async (adapter: CustomAdapter): Promise<string> => {
      const failure = await adapter
        .create({ model: 'user', data: { email: 'n@example.com' } })
        .then(
          () => null,
          (error: unknown) => error
        )
      expect(failure).toBeInstanceOf(AdapterOperationError)
      const cause = (failure as Error).cause
      expect(cause).toBeInstanceOf(UnsupportedSchemaError)
      return (cause as Error).message
    }
    const missing = fakePayload({}, {})
    expect(
      await schemaFailure(rawAdapter(missing.payload, { schemaMap: { user: { slug: 'users' } } }))
    ).toMatch(/expects collection "users"/)
    const unmapped = fakePayload({}, { users: hostUsers })
    expect(
      await schemaFailure(
        rawAdapter(unmapped.payload, {
          schemaMap: { user: { slug: 'users', fields: { image: 'avatar' } } },
        })
      )
    ).toMatch(/maps "image" to "users.avatar"/)
    const lacking = fakePayload(
      {},
      { users: { config: { auth: true, fields: [{ name: 'email', type: 'email' }] } } }
    )
    expect(
      await schemaFailure(rawAdapter(lacking.payload, { schemaMap: { user: { slug: 'users' } } }))
    ).toMatch(/needs a "users.name" field/)
  })

  it('validates every adopted model, even when the first operation plans another one', async () => {
    // Issue #113: validation used to cover only the models planned by
    // the first operation, so a read of another model first left the
    // adopted users collection unchecked (and its ids unclassified).
    const lacking = fakePayload(
      { find: () => Promise.resolve({ docs: [] }) },
      { users: { config: { auth: true, fields: [{ name: 'email', type: 'email' }] } } }
    )
    const adapter = rawAdapter(lacking.payload, { schemaMap: { user: { slug: 'users' } } })
    const failure = await adapter
      .findOne({ model: 'verification', where: [eq('identifier', 'x')] })
      .then(
        () => null,
        (error: unknown) => error
      )
    expect(failure).toBeInstanceOf(AdapterOperationError)
    expect(((failure as Error).cause as Error).message).toMatch(/needs a "users.name" field/)
  })

  it('tolerates an adopted collection without an OPTIONAL Better Auth field', async () => {
    // e.g. Better Auth 1.7's optional `jwks.expiresAt` on a payload-auth
    // layout: writes to it are dropped, reads see it unset. A missing
    // REQUIRED field still fails fast (above).
    const { payload } = fakePayload(
      { find: () => Promise.resolve({ docs: [] }) },
      {
        users: {
          config: {
            auth: { disableLocalStrategy: true },
            fields: [
              { name: 'email', type: 'email' },
              { name: 'name', type: 'text' },
              { name: 'emailVerified', type: 'checkbox' },
              { name: 'createdAt', type: 'date' },
              { name: 'updatedAt', type: 'date' },
            ],
          },
        },
      }
    )
    const adapter = rawAdapter(payload, { schemaMap: { user: { slug: 'users' } } })
    expect(
      await adapter.findOne({ model: 'user', where: [eq('email', 'n@example.com')] })
    ).toBeNull()
  })

  it('coerces renamed relationship ids to the host id type on writes', async () => {
    const hostSessions = {
      config: {
        fields: [
          { name: 'user', type: 'relationship' },
          { name: 'token', type: 'text' },
          { name: 'expiresAt', type: 'date' },
          { name: 'ipAddress', type: 'text' },
          { name: 'userAgent', type: 'text' },
          { name: 'createdAt', type: 'date' },
          { name: 'updatedAt', type: 'date' },
        ],
      },
    }
    const { payload, mocks } = fakePayload(
      { create: (args) => Promise.resolve({ id: 3, ...(args.data as object) }) },
      { userSessions: hostSessions }
    )
    const adapter = rawAdapter(payload, {
      schemaMap: { session: { slug: 'userSessions', fields: { userId: 'user' } } },
      idStrategy: 'payload',
    })
    const created = await adapter.create<Record<string, unknown>>({
      model: 'session',
      data: { userId: '42', token: 't', expiresAt: new Date('2030-01-01T00:00:00.000Z') },
    })
    const data = mocks.create.mock.calls[0]?.[0]?.data as Record<string, unknown>
    expect(data.user).toBe(42)
    expect(data.expiresAt).toBe('2030-01-01T00:00:00.000Z')
    // Reads normalize the relationship id back to a string.
    expect(created.userId).toBe('42')
    expect(created.id).toBe('3')
  })
})

describe('createSchema', () => {
  it('generates nothing: Payload owns the schema', async () => {
    const adapter = rawAdapter(fakePayload().payload)
    const generated = await adapter.createSchema?.({ file: undefined, tables: {} } as never)
    expect(generated?.path).toBe('better-auth-payload-schema.txt')
    expect((await adapter.createSchema?.({ file: 'x.ts', tables: {} }))?.path).toBe('x.ts')
  })
})
