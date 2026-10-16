/**
 * Differential suite: the Payload adapter (real Payload, SQLite in
 * memory) against Better Auth's own `memoryAdapter` as the oracle.
 * Both run behind Better Auth's adapter factory with the same options
 * and identical seeded rows; every operator, `null` handling, the
 * case-insensitive mode, sorting, and `limit`/`offset` pagination must
 * agree. Where they legitimately differ, the difference is the one
 * documented on `createPayloadDatabaseAdapter` and in
 * docs/guide-better-auth.md ("Query semantics and sort collation"), and
 * it is asserted explicitly here:
 *
 * - string sort collation: database binary order vs `localeCompare`;
 * - operators with no faithful Payload translation fail loud
 *   (`UnsupportedOperatorError`, wrapped in `AdapterOperationError`).
 *
 * Unordered reads compare as id sets (row order without `sortBy` is
 * unspecified); sorted reads compare the ordered sort-key sequence plus
 * the id set, so ties cannot make the suite flaky.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { BetterAuthOptions } from 'better-auth'
import { memoryAdapter } from 'better-auth/adapters/memory'
import { buildConfig, getPayload, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { AdapterOperationError } from '../errors.js'

const ORIGIN = 'http://adapter-differential.test'
const SECRET = 'adapter-differential-secret-32-chars!'

const options: BetterAuthOptions = {
  baseURL: ORIGIN,
  trustedOrigins: [ORIGIN],
  secret: SECRET,
  emailAndPassword: { enabled: true, requireEmailVerification: false },
  user: {
    additionalFields: {
      grp: { type: 'string', required: false },
      age: { type: 'number', required: false },
      nickname: { type: 'string', required: false },
      seenAt: { type: 'date', required: false },
    },
  },
}

let latePayload: Payload | undefined
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  customFields: {
    user: [
      { name: 'grp', type: 'text' },
      { name: 'age', type: 'number' },
      { name: 'nickname', type: 'text' },
      { name: 'seenAt', type: 'date' },
    ],
  },
  options,
})

const memoryDb: Record<string, Record<string, unknown>[]> = {
  user: [],
  session: [],
  account: [],
  verification: [],
}
const oracle = memoryAdapter(memoryDb)(options)

type Adapter = Pick<typeof oracle, 'create' | 'findMany' | 'findOne' | 'count'>
type FindManyArgs = Parameters<Adapter['findMany']>[0]
type WhereList = NonNullable<FindManyArgs['where']>
type Row = { id: string } & Record<string, unknown>

let subject: Adapter

const day = (iso: string) => new Date(`${iso}T00:00:00.000Z`)

/**
 * Two groups: `lower` (all-lowercase names — collation-neutral, so the
 * adapters must agree on every sort) and `mixed` (mixed-case names —
 * where the documented collation difference shows). Every optional
 * field is set explicitly (`null` included): the memory adapter tells
 * a missing key from `null` in `ne null`, a storage artefact the
 * Payload columns cannot reproduce.
 */
const seed = [
  { id: 'u01', name: 'delta', age: 40, nickname: 'dd', seenAt: day('2024-04-01'), ev: true },
  { id: 'u02', name: 'alpha', age: 10, nickname: null, seenAt: day('2024-01-01'), ev: false },
  { id: 'u03', name: 'charlie', age: 30, nickname: 'cc', seenAt: day('2024-03-01'), ev: true },
  { id: 'u04', name: 'bravo', age: 20, nickname: null, seenAt: day('2024-02-01'), ev: false },
  { id: 'u05', name: 'echo', age: 50, nickname: 'ee', seenAt: day('2024-05-01'), ev: true },
  { id: 'u06', name: 'foxtrot', age: 60, nickname: 'ff', seenAt: day('2024-06-01'), ev: false },
].map(({ ev, ...row }) => ({ ...row, grp: 'lower', email: `${row.name}@x.dev`, emailVerified: ev }))

const mixedSeed = [
  { id: 'm1', name: 'Banana', age: 71 },
  { id: 'm2', name: 'apple', age: 72 },
  { id: 'm3', name: 'Apple', age: 73 },
  { id: 'm4', name: 'banana', age: 74 },
].map((row) => ({
  ...row,
  grp: 'mixed',
  email: `${row.id}@x.dev`,
  emailVerified: true,
  nickname: null,
  seenAt: day('2025-01-01'),
}))

beforeAll(async () => {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
  })
  latePayload = await getPayload({ config })
  subject = (await engine.auth.$context).adapter
  for (const row of [...seed, ...mixedSeed]) {
    await subject.create({ model: 'user', data: { ...row }, forceAllowId: true })
    await oracle.create({ model: 'user', data: { ...row }, forceAllowId: true })
  }
}, 120_000)

afterAll(async () => {
  await latePayload?.db.destroy?.()
})

const ids = (rows: readonly Row[]) => rows.map((row) => row.id).sort()

async function both(args: FindManyArgs): Promise<{ actual: Row[]; expected: Row[] }> {
  const [actual, expected] = await Promise.all([
    subject.findMany<Row>(args),
    oracle.findMany<Row>(args),
  ])
  return { actual, expected }
}

/** Every `where` the adapter translates, by operator × value type. */
const agreeing: readonly (readonly [string, WhereList])[] = [
  ['eq string', [{ field: 'name', value: 'charlie', operator: 'eq' }]],
  ['eq number', [{ field: 'age', value: 20, operator: 'eq' }]],
  ['eq boolean', [{ field: 'emailVerified', value: true, operator: 'eq' }]],
  ['eq id', [{ field: 'id', value: 'u03', operator: 'eq' }]],
  ['eq (default operator)', [{ field: 'name', value: 'echo' }]],
  ['eq no match', [{ field: 'name', value: 'zulu', operator: 'eq' }]],
  ['ne string', [{ field: 'name', value: 'charlie', operator: 'ne' }]],
  ['ne number', [{ field: 'age', value: 20, operator: 'ne' }]],
  ['ne over nullable (null rows kept)', [{ field: 'nickname', value: 'dd', operator: 'ne' }]],
  ['lt number', [{ field: 'age', value: 30, operator: 'lt' }]],
  ['lte number', [{ field: 'age', value: 30, operator: 'lte' }]],
  ['gt number', [{ field: 'age', value: 30, operator: 'gt' }]],
  ['gte number', [{ field: 'age', value: 30, operator: 'gte' }]],
  ['lt date', [{ field: 'seenAt', value: day('2024-03-01'), operator: 'lt' }]],
  ['lte date', [{ field: 'seenAt', value: day('2024-03-01'), operator: 'lte' }]],
  ['gt date', [{ field: 'seenAt', value: day('2024-03-01'), operator: 'gt' }]],
  ['gte date', [{ field: 'seenAt', value: day('2024-03-01'), operator: 'gte' }]],
  ['lt string (same case)', [{ field: 'name', value: 'charlie', operator: 'lt' }]],
  ['gte string (same case)', [{ field: 'name', value: 'charlie', operator: 'gte' }]],
  ['in strings', [{ field: 'name', value: ['alpha', 'echo', 'zulu'], operator: 'in' }]],
  ['in numbers', [{ field: 'age', value: [10, 60], operator: 'in' }]],
  ['in ids', [{ field: 'id', value: ['u01', 'm2'], operator: 'in' }]],
  ['in (no match)', [{ field: 'name', value: ['zulu'], operator: 'in' }]],
  ['not_in strings', [{ field: 'name', value: ['alpha', 'echo'], operator: 'not_in' }]],
  ['not_in numbers', [{ field: 'age', value: [10, 60, 71], operator: 'not_in' }]],
  ['eq null', [{ field: 'nickname', value: null, operator: 'eq' }]],
  ['ne null', [{ field: 'nickname', value: null, operator: 'ne' }]],
  [
    'AND',
    [
      { field: 'grp', value: 'lower', operator: 'eq' },
      { field: 'emailVerified', value: false, operator: 'eq', connector: 'AND' },
    ],
  ],
  [
    'OR',
    [
      { field: 'name', value: 'alpha', operator: 'eq' },
      { field: 'age', value: 74, operator: 'eq', connector: 'OR' },
    ],
  ],
  [
    'mixed AND/OR folds left-associatively',
    [
      { field: 'age', value: 20, operator: 'lte' },
      { field: 'age', value: 60, operator: 'eq', connector: 'OR' },
      { field: 'emailVerified', value: false, operator: 'eq', connector: 'AND' },
    ],
  ],
  [
    'OR then AND with null',
    [
      { field: 'nickname', value: null, operator: 'eq' },
      { field: 'name', value: 'echo', operator: 'eq', connector: 'OR' },
      { field: 'grp', value: 'lower', operator: 'eq', connector: 'AND' },
    ],
  ],
  [
    'eq insensitive (lower group)',
    [{ field: 'name', value: 'ALPHA', operator: 'eq', mode: 'insensitive' }],
  ],
  [
    'eq insensitive (mixed case)',
    [{ field: 'name', value: 'aPPle', operator: 'eq', mode: 'insensitive' }],
  ],
  [
    'eq insensitive AND another clause',
    [
      { field: 'name', value: 'BANANA', operator: 'eq', mode: 'insensitive' },
      { field: 'age', value: 72, operator: 'gt', connector: 'AND' },
    ],
  ],
  [
    'eq sensitive keeps case',
    [{ field: 'name', value: 'Apple', operator: 'eq', mode: 'sensitive' }],
  ],
]

describe('Payload adapter vs memoryAdapter: where operators', () => {
  it.each(agreeing)('%s', async (_label, where) => {
    const { actual, expected } = await both({ model: 'user', where: [...where], limit: 100 })
    expect(ids(actual)).toEqual(ids(expected))
    const [counted, oracleCount] = await Promise.all([
      subject.count({ model: 'user', where: [...where] }),
      oracle.count({ model: 'user', where: [...where] }),
    ])
    expect(counted).toBe(oracleCount)
    // findOne agrees on presence (which row comes first is unspecified).
    const [one, oracleOne] = await Promise.all([
      subject.findOne<Row>({ model: 'user', where: [...where] }),
      oracle.findOne<Row>({ model: 'user', where: [...where] }),
    ])
    expect(one === null).toBe(oracleOne === null)
    if (one !== null) {
      expect(ids(expected)).toContain(one.id)
    }
  })

  it('round-trips every field identically', async () => {
    const { actual, expected } = await both({
      model: 'user',
      where: [{ field: 'grp', value: 'lower', operator: 'eq' }],
      limit: 100,
      sortBy: { field: 'age', direction: 'asc' },
    })
    const pick = (row: Row) => ({
      id: row.id,
      name: row.name,
      email: row.email,
      emailVerified: row.emailVerified,
      age: row.age,
      nickname: row.nickname,
      seenAt: row.seenAt,
    })
    expect(actual.map(pick)).toEqual(expected.map(pick))
  })

  // Documented difference: no faithful Payload translation exists, so
  // the adapter refuses where the memory adapter evaluates in-process.
  const refused: readonly (readonly [string, WhereList])[] = [
    ['contains', [{ field: 'name', value: 'ha', operator: 'contains' }]],
    ['starts_with', [{ field: 'name', value: 'al', operator: 'starts_with' }]],
    ['ends_with', [{ field: 'name', value: 'ta', operator: 'ends_with' }]],
    ['ne insensitive', [{ field: 'name', value: 'ALPHA', operator: 'ne', mode: 'insensitive' }]],
    ['in insensitive', [{ field: 'name', value: ['ALPHA'], operator: 'in', mode: 'insensitive' }]],
    [
      'not_in insensitive',
      [{ field: 'name', value: ['ALPHA'], operator: 'not_in', mode: 'insensitive' }],
    ],
    [
      // The post-filter is AND-ed over the whole result, so under an OR
      // it would drop rows the other branch admits: refused (issue #86).
      'eq insensitive OR another clause',
      [
        { field: 'name', value: 'ALPHA', operator: 'eq', mode: 'insensitive' },
        { field: 'age', value: 60, operator: 'eq', connector: 'OR' },
      ],
    ],
  ]

  it.each(refused)('%s fails loud instead of mistranslating', async (_label, where) => {
    const expected = await oracle.findMany<Row>({ model: 'user', where: [...where], limit: 100 })
    expect(expected.length).toBeGreaterThan(0)
    await expect(
      subject.findMany<Row>({ model: 'user', where: [...where], limit: 100 })
    ).rejects.toBeInstanceOf(AdapterOperationError)
  })
})

describe('Payload adapter vs memoryAdapter: sorting and pagination', () => {
  const lower: WhereList = [{ field: 'grp', value: 'lower', operator: 'eq' }]

  it.each([
    ['name', 'asc'],
    ['name', 'desc'],
    ['age', 'asc'],
    ['age', 'desc'],
    ['seenAt', 'asc'],
    ['seenAt', 'desc'],
    ['emailVerified', 'asc'],
    ['nickname', 'asc'],
    ['nickname', 'desc'],
  ] as const)('sortBy %s %s agrees (collation-neutral data)', async (field, direction) => {
    const { actual, expected } = await both({
      model: 'user',
      where: [...lower],
      limit: 100,
      sortBy: { field, direction },
    })
    // The sort-key sequence (not ids): ties (null nicknames, equal
    // booleans) may legally come back in either order.
    expect(actual.map((row) => row[field])).toEqual(expected.map((row) => row[field]))
    expect(ids(actual)).toEqual(ids(expected))
  })

  it.each([
    [0, 2],
    [2, 2],
    [4, 2],
    [5, 3],
    [6, 2],
    [10, 5],
  ])('offset %i limit %i pages identically', async (offset, limit) => {
    for (const direction of ['asc', 'desc'] as const) {
      const { actual, expected } = await both({
        model: 'user',
        where: [...lower],
        limit,
        offset,
        sortBy: { field: 'age', direction },
      })
      expect(actual.map((row) => row.id)).toEqual(expected.map((row) => row.id))
    }
  })

  it('pages identically under a post-filtered (case-insensitive) where', async () => {
    const where: WhereList = [
      { field: 'name', value: 'BANANA', operator: 'eq', mode: 'insensitive' },
    ]
    for (const offset of [0, 1, 2]) {
      const { actual, expected } = await both({
        model: 'user',
        where: [...where],
        limit: 1,
        offset,
        sortBy: { field: 'age', direction: 'asc' },
      })
      expect(actual.map((row) => row.id)).toEqual(expected.map((row) => row.id))
    }
  })

  it('pages the whole table without overlap or loss (numeric sort)', async () => {
    const seen: string[] = []
    const oracleSeen: string[] = []
    for (let offset = 0; offset < 12; offset += 3) {
      const { actual, expected } = await both({
        model: 'user',
        limit: 3,
        offset,
        sortBy: { field: 'age', direction: 'asc' },
      })
      seen.push(...actual.map((row) => row.id))
      oracleSeen.push(...expected.map((row) => row.id))
    }
    expect(seen).toEqual(oracleSeen)
    expect(new Set(seen).size).toBe(seed.length + mixedSeed.length)
  })

  it('documented difference: mixed-case string sort is database binary order, not localeCompare', async () => {
    const { actual, expected } = await both({
      model: 'user',
      where: [{ field: 'grp', value: 'mixed', operator: 'eq' }],
      limit: 100,
      sortBy: { field: 'name', direction: 'asc' },
    })
    // SQLite (and MongoDB) order by code point: upper case first.
    expect(actual.map((row) => row.name)).toEqual(['Apple', 'Banana', 'apple', 'banana'])
    // Better Auth's memory adapter orders with localeCompare.
    expect(expected.map((row) => row.name)).toEqual(['apple', 'Apple', 'banana', 'Banana'])
    // Same rows, different order: a pure collation difference.
    expect(ids(actual)).toEqual(ids(expected))
    const names = mixedSeed.map((row) => row.name)
    expect(actual.map((row) => row.name)).toEqual(
      [...names].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    )
    expect(expected.map((row) => row.name)).toEqual([...names].sort((a, b) => a.localeCompare(b)))
  })

  it('documented difference: paging a mixed-case string sort cuts different windows', async () => {
    const { actual, expected } = await both({
      model: 'user',
      where: [{ field: 'grp', value: 'mixed', operator: 'eq' }],
      limit: 2,
      offset: 0,
      sortBy: { field: 'name', direction: 'asc' },
    })
    expect(actual.map((row) => row.name)).toEqual(['Apple', 'Banana'])
    expect(expected.map((row) => row.name)).toEqual(['apple', 'Apple'])
  })
})
