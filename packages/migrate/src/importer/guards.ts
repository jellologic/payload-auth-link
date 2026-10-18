import { isRecord } from '@payload-auth-link/core'
import { randomBytes } from 'node:crypto'
import type { Payload } from 'payload'
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

/** Payload's key-value store, reached structurally (Payload 3.6x+). */
type KeyValueStore = {
  readonly get: (key: string) => Promise<unknown>
  readonly set: (key: string, value: NonNullable<unknown>) => Promise<void>
  readonly keys: () => Promise<string[]>
}

function keyValueStore(payload: Payload): KeyValueStore | null {
  const kv: unknown = (payload as { kv?: unknown }).kv
  if (
    isRecord(kv) &&
    typeof kv['get'] === 'function' &&
    typeof kv['set'] === 'function' &&
    typeof kv['keys'] === 'function'
  ) {
    return kv as unknown as KeyValueStore
  }
  return null
}

const storePrefix = 'payload-auth-link/migrate/'
const markerPrefix = `${storePrefix}finalized/`

/**
 * The store, or a thrown error naming the fix. Every manifest-driven
 * write reads its database record there and FAILS CLOSED without it
 * (GHSA-crrr-3cg7-f6jw): an unreadable store is never read as "not
 * finalized" or "no other run".
 */
function requireStore(payload: Payload, action: string): KeyValueStore {
  const kv = keyValueStore(payload)
  if (kv === null) {
    throw new Error(
      `this Payload version exposes no key-value store (payload.kv); ${action} reads and records the migration's database record there — upgrade Payload to a release in the kit's supported band`
    )
  }
  return kv
}

async function storeCall<T>(action: string, call: () => Promise<T>): Promise<T> {
  try {
    return await call()
  } catch (error) {
    throw new Error(
      `${action}: Payload's key-value store (the payload-kv collection) could not be read or written: ${error instanceof Error ? error.message : String(error)} — create its table (run your Payload migrations) and re-run; nothing was changed`,
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
      "this Payload version exposes no key-value store (payload.kv); finalize records its marker there — upgrade Payload to a release in the kit's supported band"
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
      `could not record the finalize marker in Payload's key-value store (the payload-kv collection): ${error instanceof Error ? error.message : String(error)} — create its table (run your Payload migrations) and re-run finalize; the manifest was not changed`,
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
}

const isRunState = (value: unknown): value is RunState =>
  value === 'open' || value === 'rolled-back' || value === 'finalized'

/**
 * This database's migration identity: a random id the kit stores in
 * the database's own key-value store, so a manifest names the database
 * it was written against. `create` mints one when none exists (the
 * first `--apply`); otherwise a missing id is `null`. Fails closed.
 */
export async function databaseIdentity(
  payload: Payload,
  options: { readonly create: boolean; readonly action: string }
): Promise<string | null> {
  const kv = requireStore(payload, options.action)
  const stored = await storeCall(options.action, () => kv.get(databaseIdKey))
  if (isRecord(stored) && typeof stored['id'] === 'string' && stored['id'] !== '') {
    return stored['id']
  }
  if (!options.create) {
    return null
  }
  const id = randomBytes(16).toString('hex')
  await storeCall(options.action, () =>
    kv.set(databaseIdKey, { id, createdAt: new Date().toISOString() })
  )
  return id
}

/** A fresh, unguessable run nonce. */
export function newRunId(): string {
  return randomBytes(16).toString('hex')
}

/** The database's record of one run, or `null` when it holds none. Fails closed. */
export async function readRun(
  payload: Payload,
  runId: string,
  action: string
): Promise<RunRecord | null> {
  const kv = requireStore(payload, action)
  const stored = await storeCall(action, () => kv.get(`${runKeyPrefix}${runId}`))
  if (
    !isRecord(stored) ||
    !isRunState(stored['state']) ||
    (stored['kind'] !== 'import' && stored['kind'] !== 'adopt-prelink') ||
    typeof stored['createdAt'] !== 'string'
  ) {
    return null
  }
  return { kind: stored['kind'], createdAt: stored['createdAt'], state: stored['state'] }
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
