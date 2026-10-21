import { describe, expect, test } from 'vitest'
import { kvAdapterOf } from '../kv-adapter.js'
import { LegacySweepError, recordStoreFor, setSkipLegacySweep } from '../importer/record-store.js'
import { requireStore } from '../importer/guards.js'
import type { Payload } from 'payload'

/**
 * Issue #132: the kit's records must live in the database they
 * describe — adapter classification, the fail-closed refusal under an
 * external KV, the collection-backed store, and its legacy sweep
 * (issue #155).
 */

const fakePayload = (kv: unknown): Parameters<typeof requireStore>[0] =>
  ({ config: { kv }, kv: { get: () => {}, set: () => {}, keys: () => {} } }) as never

const RECORDS = 'payload-auth-link-migrations'

const upstash = (): Record<string, unknown> => ({
  get: () => Promise.resolve(null),
  set: () => Promise.resolve(),
  keys: () => Promise.reject(new Error('ERR too many keys to fetch, please use SCAN')),
})

type Row = { id: number; key: string; data: unknown }

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
  } as unknown as Payload
}

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
    const external = {
      config: {
        kv: { init: () => ({}) },
        collections: [{ slug: RECORDS, fields: [] }],
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
  test('writes and reads route to the collection; the app KV is untouched', async () => {
    const rows: Row[] = []
    const kv: Record<string, unknown> = {}
    const payload = collectionPayload(rows, kv)
    const store = recordStoreFor(payload)
    if (store === null) {
      throw new Error('unreachable: the records collection is declared')
    }
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
    const store = recordStoreFor(payload)
    if (store === null) {
      throw new Error('unreachable: the records collection is declared')
    }
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
    const store = recordStoreFor(payload)
    if (store === null) {
      throw new Error('unreachable: the records collection is declared')
    }
    const keys = await store.keys()
    expect(keys).toContain('payload-auth-link/migrate/database-id')
    expect(keys).toContain('payload-auth-link/migrate/finalized/import/2020')
  })

  test('a missing records collection with no KV at all still refuses', () => {
    const bare = { config: {}, kv: undefined } as never
    expect(() => requireStore(bare, 'rollback')).toThrow(/no migration-records store is available/)
  })
})

describe('the legacy sweep on a large Redis-backed KV (issue #155)', () => {
  /** A payload whose config declares the records collection; the KV is raw. */
  function declaredPayload(kv: unknown): Payload {
    return {
      config: {
        kv: { init: () => ({}) },
        collections: [{ slug: RECORDS, fields: [] }],
      },
      kv,
      find: () => Promise.resolve({ docs: [] }),
    } as unknown as Payload
  }

  test('the sweep failure names the legacy KV and offers --no-legacy-kv', async () => {
    setSkipLegacySweep(false)
    const payload = declaredPayload(upstash())
    const store = recordStoreFor(payload)
    if (store === null) {
      throw new Error('unreachable: the records collection is declared')
    }
    await expect(store.keys()).rejects.toThrowError(LegacySweepError)
    await expect(store.keys()).rejects.toThrow(/--no-legacy-kv/)
    await expect(store.keys()).rejects.not.toThrow(/Payload migrations/)
  })

  test('--no-legacy-kv: the collection is the only store, the KV is never touched', async () => {
    setSkipLegacySweep(true)
    const rows: Row[] = []
    let kvTouched = false
    const payload = collectionPayload(rows, {
      get: () => {
        kvTouched = true
        return Promise.resolve(null)
      },
      set: () => {
        kvTouched = true
        return Promise.resolve()
      },
      keys: () => {
        kvTouched = true
        return Promise.reject(new Error('ERR too many keys to fetch, please use SCAN'))
      },
    })
    const store = recordStoreFor(payload)
    if (store === null) {
      throw new Error('unreachable: the records collection is declared')
    }
    await store.set('payload-auth-link/migrate/database-id', { id: 'db-x' })
    expect(await store.get('payload-auth-link/migrate/database-id')).toEqual({ id: 'db-x' })
    expect(await store.keys()).toEqual(['payload-auth-link/migrate/database-id'])
    expect(kvTouched).toBe(false)
    setSkipLegacySweep(false)
  })

  test('a failing legacy keys() surfaces as the sweep error, not a missing store', async () => {
    setSkipLegacySweep(false)
    const payload = declaredPayload(upstash())
    const store = recordStoreFor(payload)
    if (store === null) {
      throw new Error('unreachable: the records collection is declared')
    }
    await expect(store.keys()).rejects.toThrowError(LegacySweepError)
  })
})
