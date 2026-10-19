import type { Payload } from 'payload'
import { describe, expect, it } from 'vitest'
import { resolveAuthTables } from '../exporters.js'
import {
  assertCreatedRowsScoped,
  baIdMismatch,
  expectedBaId,
  finalizeMarkerKey,
  finalizeMarkerState,
  hostRolesField,
  recordFinalizeMarker,
  targetSlugsOf,
} from '../importer/guards.js'
import { restorableFieldsFor } from '../importer/host-writes.js'
import { resolveSourceTables } from '../importer/types.js'

const slugs = targetSlugsOf()

describe('created-row scoping', () => {
  it('maps each source key to the importer’s deterministic baId', () => {
    expect(expectedBaId('user:7')).toEqual({ model: 'user', baId: '7' })
    expect(expectedBaId('account:3')).toEqual({ model: 'account', baId: 'acct-3' })
    expect(expectedBaId('jwks:1')).toEqual({ model: 'jwks', baId: 'jwks-1' })
    expect(expectedBaId('edited')).toBeNull()
    expect(expectedBaId('users:1')).toBeNull()
    expect(expectedBaId('session:')).toBeNull()
  })

  it('accepts rows in the import’s own target collections', () => {
    expect(() =>
      assertCreatedRowsScoped(
        {
          kind: 'import',
          created: [
            { collection: 'ba-users', id: 1, sourceKey: 'user:1' },
            { collection: 'ba-jwks', id: 2, sourceKey: 'jwks:9' },
          ],
        },
        slugs
      )
    ).not.toThrow()
  })

  it('refuses a host collection, whatever the source key claims', () => {
    for (const row of [
      { collection: 'jwks', id: 1, sourceKey: 'jwks:1' },
      { collection: 'users', id: 1, sourceKey: 'user:1' },
      { collection: 'payload-preferences', id: 1, sourceKey: 'user:1' },
    ]) {
      expect(() => assertCreatedRowsScoped({ kind: 'import', created: [row] }, slugs)).toThrow(
        /outside the import's target collections/
      )
    }
  })

  it('refuses a source key whose model is not the collection’s model', () => {
    expect(() =>
      assertCreatedRowsScoped(
        { kind: 'import', created: [{ collection: 'ba-users', id: 1, sourceKey: 'session:1' }] },
        slugs
      )
    ).toThrow(/outside/)
  })

  it('treats a legacy (kind-less) manifest as an import, and honors --slugs', () => {
    const custom = targetSlugsOf({ jwks: 'auth-jwks' })
    const row = { collection: 'auth-jwks', id: 1, sourceKey: 'jwks:1' }
    expect(() => assertCreatedRowsScoped({ created: [row] }, custom)).not.toThrow()
    expect(() => assertCreatedRowsScoped({ created: [row] }, slugs)).toThrow(/outside/)
  })

  it('refuses ANY created row on an adopt-prelink manifest', () => {
    expect(() =>
      assertCreatedRowsScoped(
        {
          kind: 'adopt-prelink',
          created: [{ collection: 'ba-users', id: 1, sourceKey: 'user:1' }],
        },
        slugs
      )
    ).toThrow(/adopt-prelink never creates/)
  })

  it('flags a present row whose baId is not the imported one', () => {
    const row = { collection: 'ba-accounts', id: 4, sourceKey: 'account:4' }
    expect(baIdMismatch(row, { id: 4, baId: 'acct-4' })).toBe(false)
    expect(baIdMismatch(row, { id: 4, baId: 'live-account' })).toBe(true)
    expect(baIdMismatch(row, { id: 4 })).toBe(true)
  })
})

/** A Payload stand-in with an in-memory key-value store. */
function fakePayload(options: {
  readonly kv?: Map<string, unknown> | 'throws' | undefined
  readonly plugins?: unknown[]
}): Payload {
  const store = options.kv
  const kv =
    store === undefined
      ? undefined
      : store === 'throws'
        ? {
            get: () => Promise.reject(new Error('relation "payload_kv" does not exist')),
            set: () => Promise.reject(new Error('relation "payload_kv" does not exist')),
            keys: () => Promise.reject(new Error('relation "payload_kv" does not exist')),
          }
        : {
            get: (key: string) => Promise.resolve(store.get(key) ?? null),
            set: (key: string, value: unknown) => {
              store.set(key, value)
              return Promise.resolve()
            },
            keys: () => Promise.resolve([...store.keys()]),
          }
  return { kv, config: { plugins: options.plugins ?? [] } } as unknown as Payload
}

describe('the database finalize marker', () => {
  const manifest = { kind: 'import' as const, createdAt: '2026-10-16T00:00:00.000Z' }

  it('is one-way: recorded by finalize, found by later checks', async () => {
    const store = new Map<string, unknown>()
    const payload = fakePayload({ kv: store })
    expect(await finalizeMarkerState(payload, manifest, { anyOfKind: false })).toBe('open')
    await recordFinalizeMarker(payload, manifest, '2026-10-17T00:00:00.000Z')
    expect(store.has(finalizeMarkerKey(manifest))).toBe(true)
    expect(await finalizeMarkerState(payload, manifest, { anyOfKind: false })).toBe('finalized')
  })

  it('widens to every manifest of the kind when createdAt is not signed', async () => {
    const store = new Map<string, unknown>()
    const payload = fakePayload({ kv: store })
    await recordFinalizeMarker(payload, manifest, '2026-10-17T00:00:00.000Z')
    const other = { ...manifest, createdAt: '2020-01-01T00:00:00.000Z' }
    expect(await finalizeMarkerState(payload, other, { anyOfKind: false })).toBe('open')
    expect(await finalizeMarkerState(payload, other, { anyOfKind: true })).toBe('finalized')
    // Another kind's marker never blocks.
    expect(
      await finalizeMarkerState(payload, { ...other, kind: 'adopt-prelink' }, { anyOfKind: true })
    ).toBe('open')
  })

  it('finalize fails loudly when the store is unavailable; checks report it', async () => {
    const broken = fakePayload({ kv: 'throws' })
    await expect(recordFinalizeMarker(broken, manifest, 'now')).rejects.toThrow(
      /migration-records store/
    )
    expect(await finalizeMarkerState(broken, manifest, { anyOfKind: true })).toBe('unavailable')
    const missing = fakePayload({})
    await expect(recordFinalizeMarker(missing, manifest, 'now')).rejects.toThrow(
      /migration-records store is available/
    )
    expect(await finalizeMarkerState(missing, manifest, { anyOfKind: false })).toBe('unavailable')
  })
})

describe('the configured host roles field (#110)', () => {
  it('reads rolesField off the payload-auth-link plugin entry', () => {
    const plugin = Object.assign(() => ({}), {
      slug: 'payload-auth-link',
      options: { rolesField: 'role' },
    })
    expect(hostRolesField(fakePayload({ plugins: [plugin] }))).toBe('role')
    const defaulted = Object.assign(() => ({}), { slug: 'payload-auth-link', options: {} })
    expect(hostRolesField(fakePayload({ plugins: [defaulted] }))).toBe('roles')
    expect(hostRolesField(fakePayload({}))).toBe('roles')
  })

  it('makes the configured field restorable, nothing else', () => {
    const restorable = restorableFieldsFor('role')
    expect(restorable.has('role')).toBe(true)
    expect(restorable.has('roles')).toBe(true)
    expect(restorable.has('password')).toBe(false)
  })
})

describe('export: every auth table (#110)', () => {
  const existing = new Set([
    'users',
    'users_role',
    'users_identities',
    'user_accounts',
    'user_sessions',
    'verifications',
    'jwks',
    'organizations',
    'organizations_tags',
    'members',
    'invitations',
    'admin_invitations',
    'ba_users',
    'ba_users_rels',
    'oauth_applications',
    'payload_kv',
    'payload_preferences',
    'posts',
  ])

  it('without a map, the default layout’s missing tables are reported', () => {
    const { missing } = resolveAuthTables(existing)
    expect(missing).toEqual(['accounts', 'sessions', 'api_keys'])
  })

  it('maps renamed and uninstalled models, then adds children, ba_* and oauth_*', () => {
    const { tables, missing } = resolveAuthTables(
      existing,
      resolveSourceTables({
        accounts: 'user_accounts',
        sessions: 'user_sessions',
        api_keys: null,
      })
    )
    expect(missing).toEqual([])
    expect(tables).toEqual([
      'users',
      'user_accounts',
      'user_sessions',
      'verifications',
      'jwks',
      'organizations',
      'members',
      'invitations',
      'users_role',
      'users_identities',
      'organizations_tags',
      'admin_invitations',
      'ba_users',
      'ba_users_rels',
      'oauth_applications',
    ])
    // Non-auth tables stay out.
    expect(tables).not.toContain('payload_kv')
    expect(tables).not.toContain('posts')
  })
})
