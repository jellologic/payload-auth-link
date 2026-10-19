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
import { openRun, recordRunEntries, startRun } from '../importer/binding.js'
import {
  assertNoFinalizeMarker,
  baIdMismatch,
  databaseFingerprint,
  databaseIdentity,
  holdsEntries,
  openRuns,
  readRun,
  recordFinalizeMarker,
  recordRun,
  targetSlugsOf,
} from '../importer/guards.js'
import { priorValue, sealValue } from '../importer/host-writes.js'
import { finalizeManifest, rollbackImport } from '../importer/lifecycle.js'
import { authenticateManifest, isBound, signManifest } from '../importer/manifest-mac.js'
import type { ImportManifest } from '../importer/types.js'

const secret = 'manifest-binding-test-secret'

type Store = Map<string, unknown>

/**
 * A Payload stand-in: a secret, a key-value store, and no collections.
 * `server` stands in for the Postgres server's identity
 * (`system_identifier` + `current_database()`).
 */
function fakePayload(
  store: Store | 'throws' | 'missing',
  server?: { readonly sid: string; readonly db: string }
): Payload {
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
    ...(server === undefined
      ? {}
      : { db: { pool: { query: () => Promise.resolve({ rows: [server] }) } } }),
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
      ).rejects.toThrow(/migration-records store/)
      await expect(assertNoFinalizeMarker(payload, 'rollback')).rejects.toThrow(
        /migration-records store/
      )
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

const T = '2026-10-18T00:00:00.000Z'

/** A signed, bound manifest of `binding`'s run holding no entries. */
function emptyManifest(binding: { databaseId: string; runId: string }): ImportManifest {
  return signManifest(secret, {
    version: 4,
    kind: 'import',
    createdAt: T,
    databaseId: binding.databaseId,
    runId: binding.runId,
    sourceDatabase: 'postgres://***@db',
    options: { sessions: 'carry' },
    created: [],
    fieldWrites: [],
    finalized: false,
    sourceCounts: {},
    totals: {},
  })
}

const markers = (store: Store): string[] =>
  [...store.keys()].filter((key) => key.startsWith('payload-auth-link/migrate/finalized/'))

describe('GHSA-xw9m-ph95-84rx: a downgraded manifest cannot replay a bound run’s values', () => {
  /** The advisory's file: a bound run's sealed roles, copied into an unsigned v2 manifest. */
  async function downgraded(store: Store): Promise<ImportManifest> {
    const bound = await boundManifest(store)
    return {
      ...unsignedBase,
      version: 2,
      created: [],
      fieldWrites: [
        {
          collection: 'users',
          id: 3,
          field: 'roles',
          sealedBefore: sealValue(secret, '["admin"]', 'users\u00003\u0000roles', {
            databaseId: bound.databaseId ?? '',
            runId: 'run-1',
          }),
        },
      ],
    }
  }

  it('rollback refuses EVERY unsigned manifest on a database that holds a migration id', async () => {
    const store = new Map<string, unknown>()
    const manifest = await downgraded(store)
    await expect(
      rollbackImport({
        payload: fakePayload(store),
        manifest,
        allowUnsignedManifest: true,
        allowUnsignedDeletes: true,
        allowPlaintextRestore: true,
      })
    ).rejects.toThrow(/has run migrate 0\.8\.0 or later/)
    // Even one restoring nothing at all.
    await expect(
      rollbackImport({
        payload: fakePayload(store),
        manifest: { ...manifest, fieldWrites: [] },
        allowUnsignedManifest: true,
      })
    ).rejects.toThrow(/has run migrate 0\.8\.0 or later/)
  })

  it('finalize refuses it too, so a forged finalize can no longer block rollback', async () => {
    const store = new Map<string, unknown>()
    const manifest = await downgraded(store)
    const path = join(tmpdir(), `pal-xw9m-${Date.now()}.json`)
    try {
      await expect(
        finalizeManifest({
          payload: fakePayload(store),
          manifest,
          path,
          allowUnsignedManifest: true,
        })
      ).rejects.toThrow(/has run migrate 0\.8\.0 or later/)
      expect(markers(store)).toEqual([])
    } finally {
      rmSync(path, { force: true })
    }
  })

  it('a run-bound value copied elsewhere does not open even where unsigned manifests are allowed', async () => {
    const manifest = await downgraded(new Map())
    // A database that never ran 0.8 (no id): the unsigned manifest
    // passes the database check, but its copied value opens for no run.
    await expect(
      rollbackImport({
        payload: fakePayload(new Map()),
        manifest,
        allowUnsignedManifest: true,
      })
    ).rejects.toThrow(/manifest names none/)
  })

  it('a genuine pre-0.6.0 manifest still rolls back on a database that never ran 0.8', async () => {
    const store = new Map<string, unknown>()
    const result = await rollbackImport({
      payload: fakePayload(store),
      manifest: { ...unsignedBase, created: [], fieldWrites: [] },
      allowUnsignedManifest: true,
    })
    expect(result).toEqual({ deleted: 0, restored: 0 })
  })
})

describe('clone detection (GHSA-xw9m-ph95-84rx)', () => {
  const original = { sid: '7400000000000000001', db: 'app' }
  const otherCluster = { sid: '7400000000000000002', db: 'app' }

  it('fingerprints the Postgres server, and nothing elsewhere', async () => {
    const one = await databaseFingerprint(fakePayload(new Map(), original))
    expect(one).toMatch(/^[0-9a-f]{32}$/)
    expect(await databaseFingerprint(fakePayload(new Map(), otherCluster))).not.toBe(one)
    expect(
      await databaseFingerprint(fakePayload(new Map(), { sid: original.sid, db: 'app_copy' }))
    ).not.toBe(one)
    expect(await databaseFingerprint(fakePayload(new Map()))).toBeNull()
  })

  it('a copy of the record on another server refuses the original’s manifest everywhere', async () => {
    const store = new Map<string, unknown>()
    const binding = await startRun(fakePayload(store, original), 'import', T, 'test', {
      exclusive: true,
    })
    const manifest = emptyManifest(binding)
    const clone = new Map(store)
    const path = join(tmpdir(), `pal-clone-${Date.now()}.json`)
    try {
      await expect(
        rollbackImport({ payload: fakePayload(clone, otherCluster), manifest })
      ).rejects.toThrow(/does not belong to it/)
      await expect(
        finalizeManifest({ payload: fakePayload(clone, otherCluster), manifest, path })
      ).rejects.toThrow(/does not belong to it/)
      await expect(
        openRun({
          payload: fakePayload(clone, otherCluster),
          manifest,
          kind: 'import',
          apply: true,
          slugs: targetSlugsOf(),
          now,
          log: noop,
        })
      ).rejects.toThrow(/does not belong to it/)
      expect(markers(clone)).toEqual([])
      // A fresh run on the clone is refused too: it would share the id.
      await expect(
        startRun(fakePayload(clone, otherCluster), 'import', T, 'test', { exclusive: true })
      ).rejects.toThrow(/does not belong to it/)
    } finally {
      rmSync(path, { force: true })
    }
  })

  it('--new-database-identity gives a clone its own id; the original’s manifests are another database’s', async () => {
    const store = new Map<string, unknown>()
    const binding = await startRun(fakePayload(store, original), 'import', T, 'test', {
      exclusive: true,
    })
    const clone = new Map(store)
    await expect(
      rollbackImport({
        payload: fakePayload(clone, otherCluster),
        manifest: emptyManifest(binding),
        identity: { newDatabaseIdentity: true },
      })
    ).rejects.toThrow(/different database/)
    const cloneId = await databaseIdentity(fakePayload(clone, otherCluster), {
      create: false,
      action: 'test',
    })
    expect(cloneId).not.toBeNull()
    expect(cloneId).not.toBe(binding.databaseId)
    // The clone's copied run belongs to the original's id: not open HERE.
    expect(await openRuns(fakePayload(clone, otherCluster), cloneId ?? '', 'test')).toEqual([])
    // The original is untouched.
    expect(
      await databaseIdentity(fakePayload(store, original), { create: false, action: 'test' })
    ).toBe(binding.databaseId)
    // With nothing to re-identify, the flag is refused rather than ignored.
    await expect(
      databaseIdentity(fakePayload(store, original), {
        create: false,
        action: 'test',
        check: { newDatabaseIdentity: true },
      })
    ).rejects.toThrow(/nothing to re-identify/)
    await expect(
      databaseIdentity(fakePayload(store, original), {
        create: false,
        action: 'test',
        check: { newDatabaseIdentity: true, databaseMoved: true },
      })
    ).rejects.toThrow(/contradict/)
  })

  it('--database-moved continues the original’s runs and re-records the fingerprint', async () => {
    const store = new Map<string, unknown>()
    const binding = await startRun(fakePayload(store, original), 'import', T, 'test', {
      exclusive: true,
    })
    const moved = new Map(store)
    const result = await rollbackImport({
      payload: fakePayload(moved, otherCluster),
      manifest: emptyManifest(binding),
      identity: { databaseMoved: true },
    })
    expect(result).toEqual({ deleted: 0, restored: 0 })
    expect(
      await databaseIdentity(fakePayload(moved, otherCluster), { create: false, action: 'test' })
    ).toBe(binding.databaseId)
  })

  it('an environment id, once recorded, must be stated by every later command', async () => {
    const store = new Map<string, unknown>()
    const binding = await startRun(fakePayload(store), 'import', T, 'test', {
      exclusive: true,
      identity: { environmentId: 'production' },
    })
    const manifest = emptyManifest(binding)
    await expect(rollbackImport({ payload: fakePayload(store), manifest })).rejects.toThrow(
      /recorded in environment 'production', and this command states none/
    )
    await expect(
      rollbackImport({
        payload: fakePayload(store),
        manifest,
        identity: { environmentId: 'staging' },
      })
    ).rejects.toThrow(/runs as 'staging'/)
    await expect(
      rollbackImport({
        payload: fakePayload(store),
        manifest,
        identity: { environmentId: 'production' },
      })
    ).resolves.toEqual({ deleted: 0, restored: 0 })
  })

  it('a record written by 0.8.0 gains the fingerprint and environment when a run starts', async () => {
    const store = new Map<string, unknown>([
      ['payload-auth-link/migrate/database-id', { id: 'id-from-0.8.0', createdAt: T }],
    ])
    // Reading never writes.
    expect(
      await databaseIdentity(fakePayload(store, original), {
        create: false,
        action: 'test',
        check: { environmentId: 'production' },
      })
    ).toBe('id-from-0.8.0')
    expect(store.get('payload-auth-link/migrate/database-id')).toEqual({
      id: 'id-from-0.8.0',
      createdAt: T,
    })
    await startRun(fakePayload(store, original), 'import', T, 'test', {
      exclusive: true,
      identity: { environmentId: 'production' },
    })
    expect(store.get('payload-auth-link/migrate/database-id')).toMatchObject({
      id: 'id-from-0.8.0',
      environmentId: 'production',
      fingerprint: await databaseFingerprint(fakePayload(store, original)),
    })
    await expect(
      databaseIdentity(fakePayload(store, otherCluster), {
        create: false,
        action: 'test',
        check: { environmentId: 'production' },
      })
    ).rejects.toThrow(/does not belong to it/)
  })
})

describe('one open run at a time (issue #116)', () => {
  it('a fresh run is refused while another run may hold rows', async () => {
    const store = new Map<string, unknown>()
    const payload = fakePayload(store)
    const first = await startRun(payload, 'import', T, 'test', { exclusive: true })
    await expect(startRun(payload, 'import', T, 'test', { exclusive: true })).rejects.toThrow(
      `another migration run is still open on this database (import run ${first.runId}`
    )
    await expect(
      openRun({
        payload,
        manifest: null,
        kind: 'adopt-prelink',
        apply: true,
        slugs: targetSlugsOf(),
        now,
        log: noop,
      })
    ).rejects.toThrow(/still open/)
    // A run known to hold nothing blocks nothing.
    await recordRunEntries(payload, 'import', first, 0, 'test')
    expect(holdsEntries({ entries: 0 })).toBe(false)
    expect(holdsEntries({})).toBe(true)
    await expect(
      startRun(payload, 'import', T, 'test', { exclusive: true })
    ).resolves.toMatchObject({ databaseId: first.databaseId })
    // A run minted only to record a rollback is not exclusive.
    await expect(
      startRun(payload, 'import', T, 'test', { exclusive: false })
    ).resolves.toMatchObject({ databaseId: first.databaseId })
  })

  it('a stale manifest of a rolled-back run does not open a second run beside the live one', async () => {
    const store = new Map<string, unknown>()
    const stale = await boundManifest(store, 'rolled-back')
    const live = await startRun(fakePayload(store), 'import', T, 'test', { exclusive: true })
    await recordRunEntries(fakePayload(store), 'import', live, 12, 'test')
    await expect(
      openRun({
        payload: fakePayload(store),
        manifest: stale,
        kind: 'import',
        apply: true,
        slugs: targetSlugsOf(),
        now,
        log: noop,
      })
    ).rejects.toThrow(/still open/)
    expect(
      (await openRuns(fakePayload(store), stale.databaseId ?? '', 'test')).map((run) => run.runId)
    ).toEqual([live.runId])
  })

  it('finalize refuses while ANOTHER open run may hold rows, and writes no marker', async () => {
    const store = new Map<string, unknown>()
    // run-1 holds rows (entries unknown: recorded by 0.8.0).
    const rowBearing = await boundManifest(store)
    // An empty run beside it.
    const empty = { databaseId: rowBearing.databaseId ?? '', runId: 'run-2', createdAt: T }
    await recordRunEntries(fakePayload(store), 'import', empty, 0, 'test')
    const path = join(tmpdir(), `pal-finalize-${Date.now()}.json`)
    try {
      await expect(
        finalizeManifest({ payload: fakePayload(store), manifest: emptyManifest(empty), path })
      ).rejects.toThrow(/another migration run is still open on this database and may hold rows/)
      expect(markers(store)).toEqual([])
      // The run that holds the rows may be finalized: the empty one blocks nothing.
      await expect(
        finalizeManifest({ payload: fakePayload(store), manifest: rowBearing, path })
      ).resolves.toMatchObject({ finalized: true })
      expect((await readRun(fakePayload(store), 'run-1', 'test'))?.state).toBe('finalized')
    } finally {
      rmSync(path, { force: true })
    }
  })

  it('an unbound (0.7.0) finalize counts every row-bearing open run as another', async () => {
    const store = new Map<string, unknown>()
    await boundManifest(store)
    const unbound = signManifest(secret, {
      ...unsignedBase,
      version: 3,
      kind: 'import',
      created: [],
      fieldWrites: [],
    })
    const path = join(tmpdir(), `pal-finalize-unbound-${Date.now()}.json`)
    try {
      await expect(
        finalizeManifest({ payload: fakePayload(store), manifest: unbound, path })
      ).rejects.toThrow(/may hold rows/)
    } finally {
      rmSync(path, { force: true })
    }
  })
})
