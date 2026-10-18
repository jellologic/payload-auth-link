/**
 * GHSA-crrr-3cg7-f6jw: a manifest is bound to its database and run,
 * unsigned manifests are terminal, and every destructive check fails
 * closed. Driven against a Payload stand-in whose key-value store is an
 * in-memory map — the refusals all happen BEFORE the first row read, so
 * no database is needed. (The CLI lifecycle suite replays the advisory's
 * end-to-end cases against the real fixture database.)
 */
import { rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Payload } from 'payload'
import { describe, expect, it } from 'vitest'
import { openRun } from '../importer/binding.js'
import {
  assertNoFinalizeMarker,
  baIdMismatch,
  databaseIdentity,
  readRun,
  recordFinalizeMarker,
  recordRun,
  targetSlugsOf,
} from '../importer/guards.js'
import { priorValue } from '../importer/host-writes.js'
import { finalizeManifest, rollbackImport } from '../importer/lifecycle.js'
import { authenticateManifest, isBound, signManifest } from '../importer/manifest-mac.js'
import type { ImportManifest } from '../importer/types.js'

const secret = 'manifest-binding-test-secret'

type Store = Map<string, unknown>

/** A Payload stand-in: a secret, a key-value store, and no collections. */
function fakePayload(store: Store | 'throws' | 'missing'): Payload {
  const kv =
    store === 'missing'
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
  return {
    secret,
    kv,
    config: { plugins: [] },
    collections: {},
    findByID: () => {
      throw new Error('no row may be read before the guards pass')
    },
  } as unknown as Payload
}

const unsignedBase: ImportManifest = {
  version: 1,
  createdAt: '2026-01-01T00:00:00.000Z',
  sourceDatabase: 'postgres://***@db',
  options: { sessions: 'carry' },
  created: [{ collection: 'ba-users', id: 9, sourceKey: 'user:live-ba-user-id' }],
  // The advisory's edit: users#3.role back to ["admin"], in plaintext.
  fieldWrites: [{ collection: 'users', id: 3, field: 'role', before: '["admin"]' }],
  finalized: false,
  sourceCounts: {},
  totals: {},
}

const noop = (): void => {}
const now = (): Date => new Date('2026-10-17T00:00:00.000Z')

/** A bound manifest of a run this store records as `state`. */
async function boundManifest(
  store: Store,
  state: 'open' | 'rolled-back' | 'finalized' = 'open'
): Promise<ImportManifest> {
  const payload = fakePayload(store)
  const databaseId = await databaseIdentity(payload, { create: true, action: 'test' })
  await recordRun(
    payload,
    'run-1',
    { kind: 'import', createdAt: '2026-10-16T00:00:00.000Z', state },
    'test'
  )
  return signManifest(secret, {
    version: 4,
    kind: 'import',
    createdAt: '2026-10-16T00:00:00.000Z',
    databaseId: databaseId ?? '',
    runId: 'run-1',
    sourceDatabase: 'postgres://***@db',
    options: { sessions: 'carry' },
    created: [{ collection: 'ba-accounts', id: 4, sourceKey: 'account:4' }],
    fieldWrites: [],
    finalized: false,
    sourceCounts: {},
    totals: {},
  })
}

describe('version-4 manifests are bound to their database and run', () => {
  it('signs as version 4, and the binding sits inside the MAC', async () => {
    const manifest = await boundManifest(new Map())
    expect(manifest.version).toBe(4)
    expect(isBound(manifest)).toBe(true)
    expect(authenticateManifest(secret, manifest)).toBe('signed')
    expect(() => authenticateManifest(secret, { ...manifest, databaseId: 'other' })).toThrow(
      /integrity check/
    )
    expect(() => authenticateManifest(secret, { ...manifest, runId: 'other' })).toThrow(
      /integrity check/
    )
    // Stripping the binding (back to a 0.7.0 shape) breaks the MAC too.
    expect(() =>
      authenticateManifest(secret, {
        ...manifest,
        version: 3,
        databaseId: undefined,
        runId: undefined,
      })
    ).toThrow(/integrity check/)
  })

  it('an unsigned manifest may not claim a binding, nor a v1 manifest another kind', () => {
    expect(() =>
      authenticateManifest(secret, { ...unsignedBase, databaseId: 'x' }, { allowUnsigned: true })
    ).toThrow(/only a signed version-4 manifest/)
    expect(() =>
      authenticateManifest(
        secret,
        { ...unsignedBase, kind: 'adopt-prelink' },
        { allowUnsigned: true }
      )
    ).toThrow(/version 1 only ever recorded imports/)
  })

  it('rollback refuses a manifest from another database (same secret)', async () => {
    const manifest = await boundManifest(new Map())
    // Another environment: the same secret, its own database id.
    const other = new Map<string, unknown>()
    await databaseIdentity(fakePayload(other), { create: true, action: 'test' })
    await expect(rollbackImport({ payload: fakePayload(other), manifest })).rejects.toThrow(
      /different database/
    )
    // A database that never ran the kit holds no id at all: same refusal.
    await expect(rollbackImport({ payload: fakePayload(new Map()), manifest })).rejects.toThrow(
      /different database/
    )
  })

  it('rollback refuses a run the database does not hold open', async () => {
    const store = new Map<string, unknown>()
    const manifest = await boundManifest(store, 'rolled-back')
    await expect(rollbackImport({ payload: fakePayload(store), manifest })).rejects.toThrow(
      /stale copy/
    )
    // An unknown run (the manifest's nonce is not recorded here).
    store.delete('payload-auth-link/migrate/runs/run-1')
    await expect(rollbackImport({ payload: fakePayload(store), manifest })).rejects.toThrow(
      /holds no record of the manifest's run/
    )
  })

  it('a resumed --apply on a rolled-back run starts fresh and carries nothing', async () => {
    const store = new Map<string, unknown>()
    const manifest = await boundManifest(store, 'rolled-back')
    const opened = await openRun({
      payload: fakePayload(store),
      manifest,
      kind: 'import',
      apply: true,
      slugs: targetSlugsOf(),
      now,
      log: noop,
    })
    expect(opened.carried).toBeNull()
    expect(opened.binding?.runId).not.toBe('run-1')
    expect((await readRun(fakePayload(store), opened.binding?.runId ?? '', 'test'))?.state).toBe(
      'open'
    )
  })

  it('finalize records the run as finalized, and refuses a rolled-back run', async () => {
    const store = new Map<string, unknown>()
    const manifest = await boundManifest(store)
    const path = join(tmpdir(), `pal-binding-${Date.now()}.json`)
    try {
      const finalized = await finalizeManifest({ payload: fakePayload(store), manifest, path })
      expect(finalized.finalized).toBe(true)
      expect((await readRun(fakePayload(store), 'run-1', 'test'))?.state).toBe('finalized')
      const other = new Map<string, unknown>()
      const rolledBack = await boundManifest(other, 'rolled-back')
      await expect(
        finalizeManifest({ payload: fakePayload(other), manifest: rolledBack, path })
      ).rejects.toThrow(/rolled back; there is nothing to finalize/)
    } finally {
      rmSync(path, { force: true })
    }
  })
})

describe('unsigned manifests are terminal (GHSA-crrr-3cg7-f6jw case 1)', () => {
  it('a resumed --apply never re-signs an unsigned manifest, whatever the flags', async () => {
    const store = new Map<string, unknown>()
    await expect(
      openRun({
        payload: fakePayload(store),
        manifest: unsignedBase,
        kind: 'import',
        apply: true,
        slugs: targetSlugsOf(),
        now,
        log: noop,
        allowUnsignedManifest: true,
        allowUnboundManifest: true,
      })
    ).rejects.toThrow(/never resumed or re-signed/)
    // Nothing was recorded for a run that never started.
    expect([...store.keys()]).toEqual([])
  })

  it('a signed manifest carrying plaintext values (laundered by an older kit) is not resumed', async () => {
    const store = new Map<string, unknown>()
    const manifest = await boundManifest(store)
    const laundered = signManifest(secret, {
      ...manifest,
      fieldWrites: [{ collection: 'users', id: 3, field: 'role', before: '["admin"]' }],
    })
    await expect(
      openRun({
        payload: fakePayload(store),
        manifest: laundered,
        kind: 'import',
        apply: true,
        slugs: targetSlugsOf(),
        now,
        log: noop,
      })
    ).rejects.toThrow(/plaintext prior values/)
  })

  it('rollback restores plaintext values only with --allow-plaintext-restore', async () => {
    const store = new Map<string, unknown>()
    const plaintextOnly: ImportManifest = { ...unsignedBase, created: [] }
    await expect(
      rollbackImport({
        payload: fakePayload(store),
        manifest: plaintextOnly,
        allowUnsignedManifest: true,
        allowUnsignedDeletes: true,
      })
    ).rejects.toThrow(/--allow-plaintext-restore/)
    // The value-level guard holds on its own, too.
    expect(() =>
      priorValue(secret, { collection: 'users', id: 3, field: 'roles', before: '1' })
    ).toThrow(/--allow-plaintext-restore/)
    expect(
      priorValue(
        secret,
        { collection: 'users', id: 3, field: 'roles', before: '["user"]' },
        undefined,
        { allowPlaintext: true }
      )
    ).toEqual(['user'])
  })

  it('a 0.7.0 signed manifest (no binding) needs --allow-unbound-manifest', async () => {
    const unbound = signManifest(secret, {
      ...unsignedBase,
      version: 3,
      kind: 'import',
      created: [],
      fieldWrites: [],
    })
    expect(unbound.version).toBe(3)
    expect(authenticateManifest(secret, unbound)).toBe('signed')
    await expect(
      rollbackImport({ payload: fakePayload(new Map()), manifest: unbound })
    ).rejects.toThrow(/--allow-unbound-manifest/)
    await expect(
      openRun({
        payload: fakePayload(new Map()),
        manifest: unbound,
        kind: 'import',
        apply: true,
        slugs: targetSlugsOf(),
        now,
        log: noop,
      })
    ).rejects.toThrow(/--allow-unbound-manifest/)
  })
})

describe('finalize markers: any kind, fail closed (GHSA-crrr-3cg7-f6jw case 2)', () => {
  it('an import finalize blocks an unsigned manifest claiming adopt-prelink', async () => {
    const store = new Map<string, unknown>()
    await recordFinalizeMarker(
      fakePayload(store),
      { kind: 'import', createdAt: '2026-10-16T00:00:00.000Z' },
      '2026-10-17T00:00:00.000Z'
    )
    const disguised: ImportManifest = {
      ...unsignedBase,
      version: 2,
      kind: 'adopt-prelink',
      created: [],
      fieldWrites: [],
      finalized: false,
    }
    await expect(
      rollbackImport({
        payload: fakePayload(store),
        manifest: disguised,
        allowUnsignedManifest: true,
        allowUnsignedDeletes: true,
      })
    ).rejects.toThrow(/records a finalized migration/)
  })

  it('an unreadable or missing store refuses the rollback instead of trusting the file', async () => {
    const flipped: ImportManifest = { ...unsignedBase, finalized: false }
    for (const payload of [fakePayload('throws'), fakePayload('missing')]) {
      await expect(
        rollbackImport({
          payload,
          manifest: flipped,
          allowUnsignedManifest: true,
          allowUnsignedDeletes: true,
          allowPlaintextRestore: true,
        })
      ).rejects.toThrow(/key-value store/)
      await expect(assertNoFinalizeMarker(payload, 'rollback')).rejects.toThrow(/key-value store/)
    }
  })
})

describe('imported rows are identifiable', () => {
  it('a row without a string baId never matches, not even user:undefined', () => {
    const row = { collection: 'ba-users', id: 1, sourceKey: 'user:undefined' }
    expect(baIdMismatch(row, { id: 1 })).toBe(true)
    expect(baIdMismatch(row, { id: 1, baId: null })).toBe(true)
    expect(baIdMismatch({ ...row, sourceKey: 'user:7' }, { id: 1, baId: 7 })).toBe(true)
    expect(baIdMismatch({ ...row, sourceKey: 'user:7' }, { id: 1, baId: '7' })).toBe(false)
  })
})
