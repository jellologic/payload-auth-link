import { describe, expect, test } from 'vitest'
import { kvAdapterOf } from '../kv-adapter.js'
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

describe('the kit refuses an external key-value adapter (issue #132)', () => {
  test('requireStore refuses, naming the reason', () => {
    const external = fakePayload({ init: () => ({}) })
    expect(() => requireStore(external, 'rollback')).toThrow(/NON-database key-value adapter/)
    expect(() => requireStore(external, 'rollback')).toThrow(/restore, branch, or clone/)
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
