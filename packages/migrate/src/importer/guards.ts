import { isRecord } from '@payload-auth-link/core'
import { createHash, randomBytes } from 'node:crypto'
import type { Payload } from 'payload'
import { LegacySweepError, recordStoreFor } from './record-store.js'
import {
  defaultTargetSlugs,
  type CreatedRow,
  type ImportManifest,
  type ManifestKind,
  type TargetModel,
  type TargetSlugMap,
} from './types.js'

/**
 * The guards every destructive manifest operation runs, independent of
 * the manifest's signature:
 *
 * - created-row scoping: a rollback only ever deletes rows the importer
 *   itself creates — rows in the import's own target collections whose
 *   deterministic `baId` matches the source key the manifest names;
 * - the finalize marker: `finalize` records the point of no return in
 *   the target DATABASE (Payload's key-value store), so a manifest file
 *   alone can never reopen a finalized migration;
 * - the database record (GHSA-crrr-3cg7-f6jw): the database's own
 *   migration id and each run's state live in the same store, so a
 *   manifest from another database or another run is refused;
 * - the host roles field the app configured on `authLink`.
 */

/** The `baId` prefix the importer stamps per model (see apply.ts). */
const baIdPrefix: Readonly<Record<TargetModel, string>> = {
  user: '',
  account: 'acct-',
  session: 'sess-',
  verification: 'ver-',
  apikey: 'key-',
  jwks: 'jwks-',
  organization: 'org-',
  member: 'member-',
  invitation: 'inv-',
}

const isTargetModel = (value: string): value is TargetModel => value in baIdPrefix

/**
 * The model and deterministic `baId` a created row's `sourceKey`
 * (`<model>:<source id>`) names, or `null` when it names none.
 */
export function expectedBaId(
  sourceKey: string
): { readonly model: TargetModel; readonly baId: string } | null {
  const colon = sourceKey.indexOf(':')
  if (colon <= 0) {
    return null
  }
  const model = sourceKey.slice(0, colon)
  const sourceId = sourceKey.slice(colon + 1)
  if (!isTargetModel(model) || sourceId === '') {
    return null
  }
  return { model, baId: `${baIdPrefix[model]}${sourceId}` }
}

/** The target slugs with the defaults filled in. */
export function targetSlugsOf(overrides?: Readonly<Record<string, string>>): TargetSlugMap {
  return { ...defaultTargetSlugs, ...(overrides ?? {}) }
}

/**
 * Refuse a manifest whose created rows reach outside what the importer
 * creates, BEFORE anything is deleted (or re-signed): an `adopt-prelink`
 * manifest creates no rows at all, and an import's rows must sit in the
 * import's own target collections, under the model their source key
 * names. Signed or not — the signature proves who wrote the file, this
 * proves the file only names the kit's own rows.
 */
export function assertCreatedRowsScoped(
  manifest: Pick<ImportManifest, 'kind' | 'created'>,
  slugs: TargetSlugMap
): void {
  if (manifest.kind === 'adopt-prelink') {
    if (manifest.created.length > 0) {
      throw new Error(
        `the adopt-prelink manifest lists ${manifest.created.length} created row(s), which adopt-prelink never creates (edited manifest?); refusing to use it — nothing was deleted`
      )
    }
    return
  }
  const bySlug = new Map<string, TargetModel>()
  for (const model of Object.keys(baIdPrefix) as TargetModel[]) {
    bySlug.set(slugs[model], model)
  }
  const outside: string[] = []
  for (const row of manifest.created) {
    const expected = expectedBaId(row.sourceKey)
    const model = bySlug.get(row.collection)
    if (model === undefined || expected === null || expected.model !== model) {
      outside.push(`${row.collection}#${String(row.id)} (${row.sourceKey})`)
    }
  }
  if (outside.length > 0) {
    throw new Error(
      `the manifest lists ${outside.length} created row(s) outside the import's target collections (${[...bySlug.keys()].join(', ')}): ${outside.slice(0, 10).join(', ')}${outside.length > 10 ? ', …' : ''}. The importer only creates rows there; refusing to use the manifest — nothing was deleted. If your engine wiring renames the targets, pass the same --slugs the import ran with`
    )
  }
}

/** A created row whose `baId` no longer matches its source key. */
export function baIdMismatch(row: CreatedRow, doc: unknown): boolean {
  const expected = expectedBaId(row.sourceKey)
  if (expected === null) {
    return true
  }
  // The stored value must BE the expected string: `String(undefined)`
  // once matched a source key of `user:undefined` (GHSA-crrr-3cg7-f6jw).
  return !isRecord(doc) || typeof doc['baId'] !== 'string' || doc['baId'] !== expected.baId
}

/** The kit's record store: get/set/keys over the kit's own records. */
type KeyValueStore = {
  readonly get: (key: string) => Promise<unknown>
  readonly set: (key: string, value: NonNullable<unknown>) => Promise<void>
  readonly keys: () => Promise<string[]>
}

function keyValueStore(payload: Payload): KeyValueStore | null {
  // Issue #139: the records live in the kit's OWN collection (in the
  // database they describe), whatever `payload.config.kv` is backed
  // by. Payloads that declare no records collection fall back to
  // `payload.kv` — the pre-#139 behavior.
  return recordStoreFor(payload)
}

const storePrefix = 'payload-auth-link/migrate/'
const markerPrefix = `${storePrefix}finalized/`

/**
 * The store, or a thrown error naming the fix. Every manifest-driven
 * write reads its database record there and FAILS CLOSED without it
 * (GHSA-crrr-3cg7-f6jw): an unreadable store is never read as "not
 * finalized" or "no other run".
 */
export function requireStore(payload: Payload, action: string): KeyValueStore {
  const kv = keyValueStore(payload)
  if (kv === null) {
    throw new Error(
      `no migration-records store is available: upgrade Payload to a release in the kit's supported band and install the payload-auth-link plugin (it declares the migration-records collection); ${action} records its database identity, runs, and finalize marker there`
    )
  }
  return kv
}

async function storeCall<T>(action: string, call: () => Promise<T>): Promise<T> {
  try {
    return await call()
  } catch (error) {
    // The legacy-sweep refusal is already operator-facing final text
    // (issue #155) — re-wrapping it would point the operator at
    // Payload migrations, which is not the fix for a KV enumeration
    // failure.
    if (error instanceof LegacySweepError) {
      throw error
    }
    throw new Error(
      `${action}: the migration-records store could not be read or written: ${error instanceof Error ? error.message : String(error)} — run the app's Payload migrations (they create the 'payload-auth-link-migrations' collection) and re-run; nothing was changed`,
      { cause: error }
    )
  }
}

/** The finalize marker key of one manifest (its kind + first-apply stamp). */
export function finalizeMarkerKey(manifest: Pick<ImportManifest, 'kind' | 'createdAt'>): string {
  return `${markerPrefix}${manifest.kind ?? 'import'}/${manifest.createdAt}`
}

/**
 * Record the point of no return in the target database. One-way: the
 * kit never deletes the marker. Throws when the store is unavailable —
 * `finalize` must not report success it cannot back.
 */
export async function recordFinalizeMarker(
  payload: Payload,
  manifest: Pick<ImportManifest, 'kind' | 'createdAt'>,
  finalizedAt: string
): Promise<void> {
  const kv = keyValueStore(payload)
  if (kv === null) {
    throw new Error(
      'no migration-records store is available: install the payload-auth-link plugin (it declares the migration-records collection); finalize records its marker there'
    )
  }
  try {
    await kv.set(finalizeMarkerKey(manifest), {
      kind: manifest.kind ?? 'import',
      createdAt: manifest.createdAt,
      finalizedAt,
    })
  } catch (error) {
    throw new Error(
      `could not record the finalize marker in the migration-records store: ${error instanceof Error ? error.message : String(error)} — run the app's Payload migrations (they create the 'payload-auth-link-migrations' collection) and re-run finalize; the manifest was not changed`,
      { cause: error }
    )
  }
}

/**
 * Whether the database says this migration was finalized. `anyOfKind`
 * widens the check to every finalized manifest of the same kind.
 * Returns `'unavailable'` when the store cannot be read. Destructive
 * callers use {@link assertNoFinalizeMarker} instead, which checks
 * EVERY kind and fails closed.
 */
export async function finalizeMarkerState(
  payload: Payload,
  manifest: Pick<ImportManifest, 'kind' | 'createdAt'>,
  options: { readonly anyOfKind: boolean }
): Promise<'finalized' | 'open' | 'unavailable'> {
  const kv = keyValueStore(payload)
  if (kv === null) {
    return 'unavailable'
  }
  try {
    if ((await kv.get(finalizeMarkerKey(manifest))) !== null) {
      return 'finalized'
    }
    if (options.anyOfKind) {
      const kindPrefix = `${markerPrefix}${manifest.kind ?? 'import'}/`
      const keys = await kv.keys()
      if (keys.some((key) => key.startsWith(kindPrefix))) {
        return 'finalized'
      }
    }
    return 'open'
  } catch {
    return 'unavailable'
  }
}

/**
 * Refuse when the database records ANY finalized migration — import or
 * adopt-prelink, whatever the manifest claims to be (GHSA-crrr-3cg7-f6jw:
 * an unsigned manifest's `kind` is the editor's to choose). Fails
 * closed: a store that cannot be read refuses too.
 */
export async function assertNoFinalizeMarker(payload: Payload, action: string): Promise<void> {
  const kv = requireStore(payload, action)
  const keys = await storeCall(action, () => kv.keys())
  if (keys.some((key) => key.startsWith(markerPrefix))) {
    throw new Error(
      `the database records a finalized migration; ${action} is no longer possible on this database (the manifest file does not override that)`
    )
  }
}

const databaseIdKey = `${storePrefix}database-id`
const runKeyPrefix = `${storePrefix}runs/`

/** What the database records about one run (GHSA-crrr-3cg7-f6jw). */
export type RunState = 'open' | 'rolled-back' | 'finalized'

/** The database's record of one run. */
export type RunRecord = {
  readonly kind: ManifestKind
  readonly createdAt: string
  readonly state: RunState
  /**
   * The database id the run was started under (migrate 0.9.0+). A run
   * record copied into a clone that has since taken its own identity
   * names the original's id, and is not this database's run.
   */
  readonly databaseId?: string | undefined
  /**
   * How many entries (created rows + captured field values) the run's
   * manifest held when it was last written (migrate 0.9.0+, issue
   * #116). `undefined`: not known — an in-flight run, one that died
   * before writing its manifest, or one recorded by 0.8.0 — and treated
   * as holding rows.
   */
  readonly entries?: number | undefined
}

const isRunState = (value: unknown): value is RunState =>
  value === 'open' || value === 'rolled-back' || value === 'finalized'

/**
 * How the operator identifies the environment a command runs in
 * (GHSA-xw9m-ph95-84rx: a database cloned after its first `--apply`
 * carries the original's migration id).
 */
export type IdentityCheck = {
  /**
   * The operator's name for this environment (`--environment-id`, or
   * `PAYLOAD_AUTH_LINK_ENVIRONMENT_ID`). Recorded with the database id
   * when a run starts; once recorded, every manifest-driven command
   * must state the same value — a clone of production run as
   * `staging` is refused instead of continuing production's runs.
   */
  readonly environmentId?: string | undefined
  /**
   * `--database-moved`: this database IS the one that recorded its
   * migration id — restored into another cluster, or renamed — and
   * continues its runs. Re-records the fingerprint and environment id.
   */
  readonly databaseMoved?: boolean | undefined
  /**
   * `--new-database-identity`: this database is a CLONE and must not
   * continue the original's runs. Mints a fresh migration id, so every
   * manifest written against the original is refused here as "another
   * database".
   */
  readonly newDatabaseIdentity?: boolean | undefined
}

/** The database-id record as stored. */
type DatabaseRecord = {
  readonly id: string
  readonly createdAt: string
  readonly fingerprint?: string | undefined
  readonly environmentId?: string | undefined
}

function databaseRecordOf(stored: unknown): DatabaseRecord | null {
  if (!isRecord(stored) || typeof stored['id'] !== 'string' || stored['id'] === '') {
    return null
  }
  const fingerprint = stored['fingerprint']
  const environmentId = stored['environmentId']
  return {
    id: stored['id'],
    createdAt: typeof stored['createdAt'] === 'string' ? stored['createdAt'] : '',
    ...(typeof fingerprint === 'string' && fingerprint !== '' ? { fingerprint } : {}),
    ...(typeof environmentId === 'string' && environmentId !== '' ? { environmentId } : {}),
  }
}

/** A query-capable pool, reached structurally (`@payloadcms/db-postgres`'s `pg` pool). */
type QueryPool = {
  readonly query: (sql: string) => Promise<{ readonly rows: readonly unknown[] }>
}

/**
 * What the database server itself says about WHICH database this is,
 * independent of any row a clone copies (GHSA-xw9m-ph95-84rx). On
 * Postgres: the cluster's `system_identifier` plus `current_database()`
 * — a dump restored into another cluster, or a `CREATE DATABASE …
 * TEMPLATE` copy, differs; a PHYSICAL copy of the cluster (a disk
 * snapshot, a promoted replica) keeps both and is not detected. SQLite
 * and MongoDB expose nothing comparable: `null` (the operator's
 * `--environment-id` is the check there). A query the server refuses
 * also yields `null` — this is a best-effort detector layered on the
 * database id, never the only guard.
 */
export async function databaseFingerprint(payload: Payload): Promise<string | null> {
  const db: unknown = (payload as { db?: unknown }).db
  const pool = isRecord(db) ? db['pool'] : undefined
  if (!isRecord(pool) || typeof pool['query'] !== 'function') {
    return null
  }
  let rows: readonly unknown[]
  try {
    const result = await (pool as unknown as QueryPool).query(
      'SELECT system_identifier::text AS sid, current_database() AS db FROM pg_control_system()'
    )
    rows = result.rows
  } catch {
    return null
  }
  const row = rows[0]
  if (!isRecord(row) || typeof row['sid'] !== 'string' || typeof row['db'] !== 'string') {
    return null
  }
  return createHash('sha256')
    .update(`postgres\u0000${row['sid']}\u0000${row['db']}`)
    .digest('hex')
    .slice(0, 32)
}

/**
 * This database's migration identity: a random id the kit stores in
 * the database's own key-value store, so a manifest names the database
 * it was written against. `create` mints one when none exists (the
 * first `--apply`); otherwise a missing id is `null`. Fails closed.
 *
 * Clone detection (GHSA-xw9m-ph95-84rx): the record also keeps the
 * server's {@link databaseFingerprint} and the operator's environment
 * id. A stored id whose fingerprint or environment no longer matches
 * belongs to the database it was COPIED from — refused unless the
 * operator says which case it is (`databaseMoved` /
 * `newDatabaseIdentity`). A record that predates either value gains it
 * when a run starts (`create`).
 */
export async function databaseIdentity(
  payload: Payload,
  options: {
    readonly create: boolean
    readonly action: string
    readonly check?: IdentityCheck | undefined
  }
): Promise<string | null> {
  const { action } = options
  const check = options.check ?? {}
  if (check.databaseMoved === true && check.newDatabaseIdentity === true) {
    throw new Error(
      `${action}: --database-moved and --new-database-identity contradict each other — pass the one that describes this database`
    )
  }
  const kv = requireStore(payload, action)
  const stored = databaseRecordOf(await storeCall(action, () => kv.get(databaseIdKey)))
  const fingerprint = await databaseFingerprint(payload)
  const environmentId =
    check.environmentId !== undefined && check.environmentId !== ''
      ? check.environmentId
      : undefined
  const mint = async (): Promise<string> => {
    const id = randomBytes(16).toString('hex')
    await storeCall(action, () =>
      kv.set(databaseIdKey, {
        id,
        createdAt: new Date().toISOString(),
        ...(fingerprint === null ? {} : { fingerprint }),
        ...(environmentId === undefined ? {} : { environmentId }),
      })
    )
    return id
  }
  if (stored === null) {
    return options.create ? mint() : null
  }
  const mismatches: string[] = []
  if (
    stored.fingerprint !== undefined &&
    fingerprint !== null &&
    stored.fingerprint !== fingerprint
  ) {
    mismatches.push(
      'the database server reports a different database than the one that recorded it (another cluster, or another database name)'
    )
  }
  if (stored.environmentId !== undefined && stored.environmentId !== environmentId) {
    mismatches.push(
      environmentId === undefined
        ? `it was recorded in environment '${stored.environmentId}', and this command states none (pass --environment-id or set PAYLOAD_AUTH_LINK_ENVIRONMENT_ID)`
        : `it was recorded in environment '${stored.environmentId}', and this command runs as '${environmentId}'`
    )
  }
  if (check.newDatabaseIdentity === true) {
    if (mismatches.length === 0) {
      throw new Error(
        `${action}: --new-database-identity found nothing to re-identify — this database's migration record matches it (no copy detected). A clone is detected by the Postgres server fingerprint, or by --environment-id when each environment states its own; nothing was changed`
      )
    }
    return mint()
  }
  if (mismatches.length > 0) {
    if (check.databaseMoved !== true) {
      throw new Error(
        `${action}: this database's migration record (payload-kv) does not belong to it — ${mismatches.join('; ')}. A database cloned after its first --apply carries the original's record and must not continue the original's runs. Nothing was changed. If this database is a CLONE, give it its own identity with --new-database-identity (the original's manifests are then refused here); if it IS the original, moved into another cluster or renamed, re-run with --database-moved`
      )
    }
  }
  // A record that predates a value gains it when a run starts; a moved
  // database re-records both.
  const record = options.create || check.databaseMoved === true
  const wantsFingerprint = fingerprint !== null && stored.fingerprint !== fingerprint
  const wantsEnvironment = environmentId !== undefined && stored.environmentId !== environmentId
  if (record && (wantsFingerprint || wantsEnvironment)) {
    await storeCall(action, () =>
      kv.set(databaseIdKey, {
        ...stored,
        ...(fingerprint === null ? {} : { fingerprint }),
        ...(environmentId === undefined ? {} : { environmentId }),
      })
    )
  }
  return stored.id
}

/** A fresh, unguessable run nonce. */
export function newRunId(): string {
  return randomBytes(16).toString('hex')
}

function runRecordOf(stored: unknown): RunRecord | null {
  if (
    !isRecord(stored) ||
    !isRunState(stored['state']) ||
    (stored['kind'] !== 'import' && stored['kind'] !== 'adopt-prelink') ||
    typeof stored['createdAt'] !== 'string'
  ) {
    return null
  }
  const databaseId = stored['databaseId']
  const entries = stored['entries']
  return {
    kind: stored['kind'],
    createdAt: stored['createdAt'],
    state: stored['state'],
    ...(typeof databaseId === 'string' && databaseId !== '' ? { databaseId } : {}),
    ...(typeof entries === 'number' && Number.isSafeInteger(entries) && entries >= 0
      ? { entries }
      : {}),
  }
}

/** The database's record of one run, or `null` when it holds none. Fails closed. */
export async function readRun(
  payload: Payload,
  runId: string,
  action: string
): Promise<RunRecord | null> {
  const kv = requireStore(payload, action)
  return runRecordOf(await storeCall(action, () => kv.get(`${runKeyPrefix}${runId}`)))
}

/**
 * Every run this database records as OPEN (issue #116), except runs a
 * clone copied from another identity. Fails closed.
 */
export async function openRuns(
  payload: Payload,
  databaseId: string,
  action: string
): Promise<readonly (RunRecord & { readonly runId: string })[]> {
  const kv = requireStore(payload, action)
  const keys = await storeCall(action, () => kv.keys())
  const open: (RunRecord & { readonly runId: string })[] = []
  for (const key of keys) {
    if (!key.startsWith(runKeyPrefix)) {
      continue
    }
    const run = runRecordOf(await storeCall(action, () => kv.get(key)))
    if (
      run !== null &&
      run.state === 'open' &&
      (run.databaseId === undefined || run.databaseId === databaseId)
    ) {
      open.push({ ...run, runId: key.slice(runKeyPrefix.length) })
    }
  }
  return open
}

/** Whether an open run may hold rows (an unknown count is assumed to). */
export function holdsEntries(run: Pick<RunRecord, 'entries'>): boolean {
  return run.entries === undefined || run.entries > 0
}

/** Record one run's state in the database. Throws when it cannot. */
export async function recordRun(
  payload: Payload,
  runId: string,
  record: RunRecord,
  action: string
): Promise<void> {
  const kv = requireStore(payload, action)
  await storeCall(action, () =>
    kv.set(`${runKeyPrefix}${runId}`, { ...record, updatedAt: new Date().toISOString() })
  )
}

/**
 * The host roles field the app configured (`authLink({ rolesField })`),
 * read off the plugin entry in the booted config (Payload keeps each
 * plugin's `slug` and `options` for cross-plugin discovery). Defaults to
 * the plugin's own default, `roles`.
 */
export function hostRolesField(payload: Payload): string {
  const plugins: unknown = (payload.config as { plugins?: unknown }).plugins
  if (Array.isArray(plugins)) {
    for (const plugin of plugins as unknown[]) {
      if (typeof plugin !== 'function') {
        continue
      }
      const entry = plugin as { slug?: unknown; options?: unknown }
      if (entry.slug !== 'payload-auth-link') {
        continue
      }
      const rolesField = isRecord(entry.options) ? entry.options['rolesField'] : undefined
      return typeof rolesField === 'string' && rolesField !== '' ? rolesField : 'roles'
    }
  }
  return 'roles'
}
