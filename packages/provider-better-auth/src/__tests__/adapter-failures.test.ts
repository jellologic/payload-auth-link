/**
 * Adapter failure reporting (issue #86): Payload's bulk `update` and
 * `delete` RESOLVE with a per-row `errors` array instead of rejecting,
 * so a partially failed `updateMany`/`deleteMany` (an access hook, a
 * validation, a locked row) would otherwise report success with a
 * smaller count — a revoke-all that silently left sessions alive.
 * The adapter must throw instead. Unbounded deletes are refused
 * outright: an empty where would wipe the whole model.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload } from 'payload'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'adapter-failures-secret-32-chars!'

let payload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!payload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(payload)
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})

async function adapter() {
  const ctx = await engine.auth.$context
  return ctx.adapter
}

function live(): Payload {
  if (!payload) {
    throw new Error('Payload not ready')
  }
  return payload
}

async function seed(baId: string, email: string): Promise<void> {
  await live().create({
    collection: 'ba-users',
    data: { baId, email, name: baId, emailVerified: false },
    overrideAccess: true,
  })
}

const partial = (count: number) => ({
  docs: [],
  errors: Array.from({ length: count }, (_, index) => ({
    id: index,
    message: `row ${index} locked`,
  })),
})

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
  payload = await getPayload({ config })
  await engine.auth.$context
  await seed('f-1', 'one@fail.dev')
  await seed('f-2', 'two@fail.dev')
  await seed('f-3', 'Mixed@Fail.dev')
}, 120_000)

afterAll(async () => {
  await payload?.db.destroy?.()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('updateMany / deleteMany partial failure', () => {
  it('updateMany throws when Payload reports failed rows (plain where)', async () => {
    vi.spyOn(live(), 'update').mockResolvedValueOnce(partial(2) as never)
    await expect(
      (await adapter()).updateMany({
        model: 'user',
        where: [{ field: 'emailVerified', value: false }],
        update: { name: 'renamed' },
      })
    ).rejects.toThrow(/updateMany user: 2 row\(s\) failed: row 0 locked; row 1 locked/)
  })

  it('updateMany throws on partial failure on the post-filtered (insensitive) path', async () => {
    vi.spyOn(live(), 'update').mockResolvedValueOnce(partial(1) as never)
    await expect(
      (await adapter()).updateMany({
        model: 'user',
        where: [{ field: 'email', value: 'mixed@fail.dev', mode: 'insensitive' }],
        update: { name: 'renamed' },
      })
    ).rejects.toThrow(/updateMany user: 1 row\(s\) failed: row 0 locked/)
  })

  it('deleteMany throws when Payload reports failed rows (plain where)', async () => {
    vi.spyOn(live(), 'delete').mockResolvedValueOnce(partial(1) as never)
    await expect(
      (await adapter()).deleteMany({
        model: 'user',
        where: [{ field: 'emailVerified', value: false }],
      })
    ).rejects.toThrow(/deleteMany user: 1 row\(s\) failed: row 0 locked/)
  })

  it('deleteMany throws on partial failure on the post-filtered (insensitive) path', async () => {
    vi.spyOn(live(), 'delete').mockResolvedValueOnce(partial(3) as never)
    await expect(
      (await adapter()).deleteMany({
        model: 'user',
        where: [{ field: 'email', value: 'MIXED@fail.dev', mode: 'insensitive' }],
      })
    ).rejects.toThrow(/deleteMany user: 3 row\(s\) failed/)
  })

  it('a malformed bulk result is an error, not a zero count', async () => {
    vi.spyOn(live(), 'update').mockResolvedValueOnce({ docs: [] } as never)
    await expect(
      (await adapter()).updateMany({
        model: 'user',
        where: [{ field: 'emailVerified', value: false }],
        update: { name: 'x' },
      })
    ).rejects.toThrow(/expected a bulk result with docs and errors/)
    vi.spyOn(live(), 'delete').mockResolvedValueOnce({ docs: [], errors: ['nope'] } as never)
    await expect(
      (await adapter()).deleteMany({
        model: 'user',
        where: [{ field: 'emailVerified', value: false }],
      })
    ).rejects.toThrow(/malformed bulk error entry/)
  })

  it('the rows survive every refused bulk write', async () => {
    const remaining = await live().count({ collection: 'ba-users', overrideAccess: true })
    expect(remaining.totalDocs).toBe(3)
  })

  it('post-filtered bulk writes with no exact match touch nothing', async () => {
    const update = vi.spyOn(live(), 'update')
    const remove = vi.spyOn(live(), 'delete')
    const a = await adapter()
    expect(
      await a.updateMany({
        model: 'user',
        // `like` matches "one@fail.dev"; the exact post-filter does not.
        where: [{ field: 'email', value: 'ne@fail.dev', mode: 'insensitive' }],
        update: { name: 'x' },
      })
    ).toBe(0)
    expect(
      await a.deleteMany({
        model: 'user',
        where: [{ field: 'email', value: 'ne@fail.dev', mode: 'insensitive' }],
      })
    ).toBe(0)
    expect(update).not.toHaveBeenCalled()
    expect(remove).not.toHaveBeenCalled()
  })
})

describe('empty where clauses', () => {
  it('delete and deleteMany refuse an empty where', async () => {
    const a = await adapter()
    await expect(a.delete({ model: 'user', where: [] })).rejects.toThrow(
      /refusing empty where clause/
    )
    await expect(a.deleteMany({ model: 'user', where: [] })).rejects.toThrow(
      /refusing empty where clause/
    )
    const remaining = await live().count({ collection: 'ba-users', overrideAccess: true })
    expect(remaining.totalDocs).toBe(3)
  })

  it('update and updateMany with an empty where touch nothing', async () => {
    const update = vi.spyOn(live(), 'update')
    const a = await adapter()
    expect(await a.update({ model: 'user', where: [], update: { name: 'all' } })).toBeNull()
    expect(await a.updateMany({ model: 'user', where: [], update: { name: 'all' } })).toBe(0)
    expect(update).not.toHaveBeenCalled()
  })
})
