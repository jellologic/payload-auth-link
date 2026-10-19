import { describe, expect, test } from 'vitest'
import { kvAdapterOf } from '../kv-adapter.js'
import type { Payload } from 'payload'
import { requireStore } from '../importer/guards.js'

/**
 * Issue #132: the kit's records must live in the database they
 * describe. Classification of the configured adapter, and the
 * fail-closed refusal on every store access under an external one.
 */

const fakePayload = (kv: unknown): Parameters<typeof requireStore>[0] =>
  ({ config: { kv }, kv: { get: () => {}, set: () => {}, keys: () => {} } }) as never

describe('kvAdapterOf (issue #132)', () => {
  test('no adapter configured: the default is database-backed', () => {
    expect(kvAdapterOf(undefined)).toBe('none')
    expect(kvAdapterOf({})).toBe('none')
    expect(kvAdapterOf({ kv: null })).toBe('none')
  })

  test('databaseKVAdapter always ships its kvCollection', () => {
    expect(kvAdapterOf({ kv: { init: () => ({}), kvCollection: { slug: 'payload-kv' } } })).toBe(
      'database'
    )
  })

  test('an adapter without a database collection is external', () => {
    expect(kvAdapterOf({ kv: { init: () => ({}) } })).toBe('external')
    expect(kvAdapterOf({ kv: 'redis-adapter-result' })).toBe('external')
    expect(kvAdapterOf({ kv: { kvCollection: 'not-a-record' } })).toBe('external')
  })
})

describe('the key-value adapter no longer gates the kit (issue #139)', () => {
  test('an external adapter is fine: the kit uses its own records collection', () => {
    // A config declaring the records collection routes to it — the
    // app's KV adapter is irrelevant.
    const external = {
      config: {
        kv: { init: () => ({}) },
        collections: [{ slug: 'payload-auth-link-migrations', fields: [] }],
      },
      kv: { get: () => {}, set: () => {}, keys: () => {} },
    } as never
    const store = requireStore(external, 'rollback')
    expect(typeof store.get).toBe('function')
  })

  test('a database-backed adapter is accepted', () => {
    const database = fakePayload({ init: () => ({}), kvCollection: { slug: 'payload-kv' } })
    const store = requireStore(database, 'rollback')
    expect(typeof store.get).toBe('function')
  })

  test('no adapter at all is accepted (the default)', () => {
    const none = fakePayload(undefined)
    expect(() => requireStore(none, 'rollback')).not.toThrow()
  })
})

describe('the collection-backed record store (issue #139)', () => {
  const RECORDS = 'payload-auth-link-migrations'
  type Row = { id: number; key: string; data: unknown }

  /** A payload whose config declares the records collection, backed by rows. */
  function collectionPayload(rows: Row[], kv?: Record<string, unknown>): Payload {
    let nextId = rows.length + 1
    return {
      config: {
        kv: kv === undefined ? undefined : { init: () => ({}) },
        collections: [{ slug: RECORDS, fields: [] }],
      },
      kv:
        kv === undefined
          ? undefined
          : {
              get: (key: string) => Promise.resolve(kv[key] ?? null),
              set: (key: string, value: unknown) => {
                kv[key] = value
                return Promise.resolve()
              },
              keys: () => Promise.resolve(Object.keys(kv)),
            },
      find: (args: { where?: { key?: { equals?: string } }; limit?: number }) => {
        const equals = (args.where as { key?: { equals?: string } } | undefined)?.key?.equals
        const matched = rows.filter((row) => (equals === undefined ? true : row.key === equals))
        return Promise.resolve({ docs: matched.slice(0, args.limit ?? matched.length) })
      },
      create: (args: { data: { key: string; data: unknown } }) => {
        rows.push({ id: nextId, key: args.data.key, data: args.data.data })
        nextId += 1
        return Promise.resolve({ id: nextId - 1 })
      },
      update: (args: { id: number; data: { data: unknown } }) => {
        const row = rows.find((row) => row.id === args.id)
        if (row) {
          row.data = args.data.data
        }
        return Promise.resolve(row)
      },
    } as never
  }

  test('writes and reads route to the collection; the app KV is untouched', async () => {
    const rows: Row[] = []
    const kv: Record<string, unknown> = {}
    const payload = collectionPayload(rows, kv)
    const store = requireStore(payload, 'rollback')
    await store.set('payload-auth-link/migrate/database-id', { id: 'db-1' })
    // The first store access also writes the legacy-migration flag.
    const written = rows.find((row) => row.key === 'payload-auth-link/migrate/database-id')
    expect(written?.data).toEqual({ id: 'db-1' })
    expect(kv).toEqual({})
    expect(await store.get('payload-auth-link/migrate/database-id')).toEqual({ id: 'db-1' })
  })

  test('legacy records migrate on first read: copied into the collection, then served from it', async () => {
    const rows: Row[] = []
    const kv: Record<string, unknown> = {
      'payload-auth-link/migrate/database-id': { id: 'db-legacy' },
      'unrelated-app-key': { keep: true },
    }
    const payload = collectionPayload(rows, kv)
    const store = requireStore(payload, 'rollback')
    expect(await store.get('payload-auth-link/migrate/database-id')).toEqual({ id: 'db-legacy' })
    // Copied over: the collection now holds it (and only kit records).
    const copied = rows.find((row) => row.key === 'payload-auth-link/migrate/database-id')
    expect(copied?.data).toEqual({ id: 'db-legacy' })
    expect(rows.some((row) => row.key === 'unrelated-app-key')).toBe(false)
    // The legacy record may disappear afterwards; the collection serves.
    delete kv['payload-auth-link/migrate/database-id']
    expect(await store.get('payload-auth-link/migrate/database-id')).toEqual({ id: 'db-legacy' })
  })

  test('keys() unions the collection with legacy records', async () => {
    const rows: Row[] = [{ id: 1, key: 'payload-auth-link/migrate/database-id', data: { id: 'x' } }]
    const kv: Record<string, unknown> = {
      'payload-auth-link/migrate/finalized/import/2020': { at: 'then' },
    }
    const payload = collectionPayload(rows, kv)
    const store = requireStore(payload, 'rollback')
    const keys = await store.keys()
    expect(keys).toContain('payload-auth-link/migrate/database-id')
    expect(keys).toContain('payload-auth-link/migrate/finalized/import/2020')
  })

  test('a missing records collection with no KV at all still refuses', () => {
    const bare = { config: {}, kv: undefined } as never
    expect(() => requireStore(bare, 'rollback')).toThrow(/no migration-records store is available/)
  })
})
