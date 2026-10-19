import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import type { Payload } from 'payload'
import type { FieldWrite, ImportManifest } from './types.js'

/**
 * Host-document field writes with exact rollback (issues #50, #88).
 *
 * Capture: before the importer (or `adopt-prelink`) writes a host
 * field, its CURRENT value is captured into the manifest — once per
 * document field, the FIRST capture wins, so a second `--apply` can
 * never overwrite the pre-import value with imported state. The
 * document's `updatedAt` is captured the same way, because the Local
 * API write bumps it.
 *
 * Privacy: captured values (identity rows and `linkableEmail` carry
 * email addresses) are sealed with AES-256-GCM under a key derived
 * from the target app's Payload `secret`; the manifest stores no value
 * in the clear. Rollback needs the same secret — it boots the same
 * app. Each value is bound (GCM associated data) to its entry AND to
 * the database id and run nonce of the manifest that captured it
 * (GHSA-xw9m-ph95-84rx), so it opens in no other manifest.
 *
 * Restore: rollback writes the captured values back through the
 * DATABASE ADAPTER (`payload.db.updateOne`), not the Local API
 * operation: the operation would stamp a fresh `updatedAt` and re-run
 * hooks, so the "restored" row would differ from the original. The
 * adapter write sets exactly the captured fields — `updatedAt`
 * included — on every adapter (Postgres, SQLite, Mongo). What it
 * cannot preserve is documented in docs/migrating-from-payload-auth.md
 * (the forward Local API write re-creates hasMany child rows such as
 * `users_role` with new row ids; their values and order are intact).
 */

/**
 * The `req.context` key the kit marks every host write with (issue
 * #123). The kit's host writes run through the HOST app's Local API, so
 * the users collection's `beforeChange` / `afterChange` hooks fire for
 * each one — `from-payload-auth --apply`, `adopt-prelink --apply`, and
 * every rollback restore alike. A host hook that triggers outward side
 * effects (a CRM sync, an email, a webhook, re-indexing) skips them for
 * migration writes by checking this key:
 *
 * ```ts
 * import { MIGRATION_CONTEXT } from '@payload-auth-link/migrate'
 *
 * // in a users-collection hook:
 * if (req.context?.[MIGRATION_CONTEXT] !== undefined) return
 * ```
 */
export const MIGRATION_CONTEXT = 'payloadAuthLinkMigration'

/** The migration command a marked host write belongs to. */
export type MigrationContextOp = 'adopt-prelink' | 'import' | 'rollback'

/** The value the kit stores under {@link MIGRATION_CONTEXT} in `req.context`. */
export type MigrationContextMarker = {
  readonly op: MigrationContextOp
}

/**
 * The `context` argument every Local API host write passes. Payload
 * merges it into `req.context`, where the host hooks read it (see
 * {@link MIGRATION_CONTEXT}); the adapter writes beside them
 * (`payload.db.updateOne`) run no hooks and carry no marker.
 */
export function migrationContextOf(op: MigrationContextOp): {
  readonly context: { readonly [MIGRATION_CONTEXT]: MigrationContextMarker }
} {
  return { context: { [MIGRATION_CONTEXT]: { op } } }
}

/** Seals written by migrate 0.5–0.8.0: bound to the entry only. */
const legacySealPrefix = 'v1.'
/** Seals written since 0.9.0: bound to the entry AND its database and run. */
const boundSealPrefix = 'v2.'

type SealScheme = 'v1' | 'v2'

const writeKey = (collection: string, id: string | number, field: string): string =>
  `${collection}\u0000${String(id)}\u0000${field}`

function keyFor(secret: string, scheme: SealScheme): Buffer {
  return createHash('sha256')
    .update(`payload-auth-link/migrate/manifest-seal/${scheme}\u0000`)
    .update(secret)
    .digest()
}

/**
 * The run a sealed value belongs to (GHSA-xw9m-ph95-84rx): the
 * database id and run nonce of the version-4 manifest that captured
 * it.
 */
export type SealScope = {
  readonly databaseId: string
  readonly runId: string
}

const boundAad = (scope: SealScope, entry: string): string =>
  `${scope.databaseId}\u0000${scope.runId}\u0000${entry}`

function seal(secret: string, scheme: SealScheme, plaintext: string, aad: string): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', keyFor(secret, scheme), iv)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  const prefix = scheme === 'v1' ? legacySealPrefix : boundSealPrefix
  return `${prefix}${Buffer.concat([iv, tag, body]).toString('base64url')}`
}

/**
 * Seal one JSON-serialized value under the app's Payload secret. The
 * entry it belongs to (`collection\0id\0field`) AND the run that
 * captured it (database id + run nonce) are bound as GCM associated
 * data (GHSA-xw9m-ph95-84rx), so a sealed value can be moved neither
 * onto another entry nor into another manifest — not even an unsigned
 * one, which names no run and therefore opens no such value.
 */
export function sealValue(
  secret: string,
  plaintext: string,
  entry: string,
  scope: SealScope
): string {
  return seal(secret, 'v2', plaintext, boundAad(scope, entry))
}

/**
 * Seal a value the way migrate 0.5–0.8.0 did (entry-bound only). The
 * kit never writes these any more; kept so the legacy read path stays
 * tested.
 */
export function sealLegacyValue(secret: string, plaintext: string, entry: string): string {
  return seal(secret, 'v1', plaintext, entry)
}

/**
 * Open a sealed value. A run-bound (`v2.`) value opens only for the
 * run that sealed it: `scope` is the database id and run nonce of the
 * (signed, database-checked) manifest it was read from, `null` for a
 * manifest that names none. An entry-bound (`v1.`) value from an older
 * kit opens on its entry alone — the caller has already decided the
 * manifest may be used (it is signed, or it is an unsigned pre-0.6.0
 * manifest on a database that never ran 0.8.0 or later). Throws when
 * the secret, the entry, or the run is not the sealing one.
 */
export function unsealValue(
  secret: string,
  sealed: string,
  entry: string,
  scope: SealScope | null
): string {
  let scheme: SealScheme
  let aad: string
  if (sealed.startsWith(boundSealPrefix)) {
    if (scope === null) {
      throw new Error(
        'cannot open the manifest: it holds a value sealed for a specific database and run, and the manifest names none (a value copied out of a version-4 manifest?) — refusing to restore it'
      )
    }
    scheme = 'v2'
    aad = boundAad(scope, entry)
  } else if (sealed.startsWith(legacySealPrefix)) {
    scheme = 'v1'
    aad = entry
  } else {
    throw new Error('manifest value is not a sealed value this kit wrote')
  }
  const prefixLength = scheme === 'v1' ? legacySealPrefix.length : boundSealPrefix.length
  const raw = Buffer.from(sealed.slice(prefixLength), 'base64url')
  const iv = raw.subarray(0, 12)
  const tag = raw.subarray(12, 28)
  const body = raw.subarray(28)
  const decipher = createDecipheriv('aes-256-gcm', keyFor(secret, scheme), iv)
  decipher.setAuthTag(tag)
  decipher.setAAD(Buffer.from(aad, 'utf8'))
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
  } catch {
    throw new Error(
      'cannot open the manifest: a value was sealed with a different PAYLOAD_SECRET, for a different entry, or for a different database or run (edited manifest) — run rollback against the same app (same secret) that ran the import, with the manifest it wrote'
    )
  }
}

/** The run scope a manifest's sealed values are opened under. */
export function sealScopeOf(
  manifest: Pick<ImportManifest, 'databaseId' | 'runId'>
): SealScope | null {
  return typeof manifest.databaseId === 'string' &&
    manifest.databaseId !== '' &&
    typeof manifest.runId === 'string' &&
    manifest.runId !== ''
    ? { databaseId: manifest.databaseId, runId: manifest.runId }
    : null
}

/**
 * The only host fields the kit ever writes (importer and
 * `adopt-prelink`), plus the `updatedAt` it captures alongside them.
 * Rollback restores nothing else: a manifest is a file on disk, and an
 * edited one must not become a way to set arbitrary fields (roles are
 * restored only because the importer writes them).
 */
export const restorableFields: ReadonlySet<string> = new Set([
  'identities',
  'roles',
  'linkable',
  'linkableEmail',
  'updatedAt',
])

/** {@link restorableFields} plus the app's configured roles field. */
export function restorableFieldsFor(rolesField: string): ReadonlySet<string> {
  return new Set([...restorableFields, rolesField])
}

/**
 * The captured prior value of one manifest entry, JSON-parsed. A
 * version-1 PLAINTEXT value is refused unless `allowPlaintext`
 * (`--allow-plaintext-restore`, GHSA-crrr-3cg7-f6jw): nothing vouches
 * for a value stored in the clear, even inside a manifest an older kit
 * re-signed.
 */
export function priorValue(
  secret: string,
  write: FieldWrite,
  restorable: ReadonlySet<string> = restorableFields,
  options: {
    readonly allowPlaintext?: boolean | undefined
    /** The manifest's run (see {@link sealScopeOf}); `null` when it names none. */
    readonly scope?: SealScope | null | undefined
  } = {}
): unknown {
  if (!restorable.has(write.field)) {
    throw new Error(
      `manifest entry for '${write.collection}.${write.field}' is not a field this kit writes; refusing to restore it (edited manifest?)`
    )
  }
  if (write.sealedBefore !== undefined) {
    return JSON.parse(
      unsealValue(
        secret,
        write.sealedBefore,
        writeKey(write.collection, write.id, write.field),
        options.scope ?? null
      )
    ) as unknown
  }
  // Version-1 manifests stored the value in the clear.
  if (write.before !== undefined && options.allowPlaintext !== true) {
    throw new Error(
      `manifest entry for '${write.collection}.${write.field}' holds a plaintext prior value, which nothing vouches for; review the manifest and pass --allow-plaintext-restore to restore it`
    )
  }
  return write.before === null || write.before === undefined
    ? null
    : (JSON.parse(write.before) as unknown)
}

/** Keys of the field writes a manifest already holds (first capture wins). */
export function capturedKeys(writes: readonly FieldWrite[]): Set<string> {
  return new Set(writes.map((write) => writeKey(write.collection, write.id, write.field)))
}

/**
 * Capture `fields` (plus `updatedAt`) of one document before it is
 * written. Fields the document does not carry are skipped — they are
 * neither written nor restored. Returns the fields the document DOES
 * carry, so the caller writes only those.
 */
export async function captureBefore(options: {
  readonly payload: Payload
  readonly collection: string
  readonly id: string | number
  readonly fields: readonly string[]
  readonly captured: Set<string>
  readonly into: FieldWrite[]
  /** The run the values are sealed for (GHSA-xw9m-ph95-84rx). */
  readonly scope: SealScope
}): Promise<{
  readonly present: ReadonlySet<string>
  readonly newlyCaptured: number
  /** The document as read before the write. */
  readonly before: Readonly<Record<string, unknown>> | undefined
}> {
  const { payload, collection, id, fields, captured, into, scope } = options
  const doc: unknown = await payload.findByID({
    collection,
    id,
    depth: 0,
    overrideAccess: true,
  })
  const record =
    typeof doc === 'object' && doc !== null ? (doc as Record<string, unknown>) : undefined
  const present = new Set<string>()
  let newlyCaptured = 0
  for (const field of [...fields, 'updatedAt']) {
    if (record === undefined || !(field in record)) {
      continue
    }
    present.add(field)
    const key = writeKey(collection, id, field)
    if (captured.has(key)) {
      // The FIRST capture is the pre-import value; a later pass would
      // only capture this tool's own earlier write (issue #88).
      continue
    }
    captured.add(key)
    into.push({
      collection,
      id,
      field,
      sealedBefore: sealValue(payload.secret, JSON.stringify(record[field] ?? null), key, scope),
    })
    newlyCaptured += 1
  }
  return { present, newlyCaptured, before: record }
}

/** A database transaction id, as `payload.db.beginTransaction` returns it. */
export type TransactionId = string | number

/** The adapter's transaction API, reached structurally (absent on some adapters). */
type TransactionApi = {
  readonly beginTransaction: () => Promise<TransactionId | null>
  readonly commitTransaction: (id: TransactionId) => Promise<void>
  readonly rollbackTransaction: (id: TransactionId) => Promise<void>
}

function transactionApi(payload: Payload): TransactionApi | null {
  const db: unknown = (payload as { db?: unknown }).db
  if (
    typeof db === 'object' &&
    db !== null &&
    typeof (db as Record<string, unknown>)['beginTransaction'] === 'function' &&
    typeof (db as Record<string, unknown>)['commitTransaction'] === 'function' &&
    typeof (db as Record<string, unknown>)['rollbackTransaction'] === 'function'
  ) {
    return db as unknown as TransactionApi
  }
  return null
}

/**
 * Run `work` inside ONE database transaction when the adapter provides
 * one (Postgres, SQLite; MongoDB on a replica set): it commits when
 * `work` resolves and rolls back when it throws, so a failed step
 * leaves nothing half-applied. `work` receives the transaction id
 * (`null` when the adapter has none — then each write commits on its
 * own, and the caller documents how a re-run completes the work).
 *
 * Every Local API call inside must pass `req: { transactionID }` (a
 * FRESH object per call) and stop at its first failure: Payload rolls
 * the shared transaction back as soon as one operation throws.
 */
export async function inTransaction<T>(
  payload: Payload,
  work: (transactionID: TransactionId | null) => Promise<T>
): Promise<T> {
  const api = transactionApi(payload)
  const id = api === null ? null : await api.beginTransaction()
  if (api === null || id === null) {
    return work(null)
  }
  let result: T
  try {
    result = await work(id)
  } catch (error) {
    await api.rollbackTransaction(id)
    throw error
  }
  await api.commitTransaction(id)
  return result
}

/** A Local API / adapter `req` carrying the transaction, or nothing. */
export function transactionReq(
  transactionID: TransactionId | null
): { readonly req: { transactionID: TransactionId } } | Record<string, never> {
  return transactionID === null ? {} : { req: { transactionID } }
}

/**
 * Write host fields through the Local API (hooks, validation, array
 * row ids) WITHOUT moving the document's `updatedAt` (issue #116):
 * Payload's update operation always stamps a fresh `updatedAt`, so the
 * captured value is written back through the adapter right after, in
 * the same transaction. Hosts and caches that key on `updated_at`
 * see the document as unchanged by the migration tooling.
 *
 * The Local API write carries {@link migrationContextOf the migration
 * context marker} (`op` names the command) so host hooks can skip
 * outward side effects; the adapter's timestamp write runs no hooks.
 */
export async function updateKeepingTimestamp(
  payload: Payload,
  options: {
    readonly collection: string
    readonly id: string | number
    readonly data: Record<string, unknown>
    readonly updatedAt: unknown
    /** The command this write belongs to (see {@link MIGRATION_CONTEXT}). */
    readonly op: MigrationContextOp
  }
): Promise<void> {
  await inTransaction(payload, async (transactionID) => {
    await payload.update({
      collection: options.collection,
      id: options.id,
      data: options.data,
      overrideAccess: true,
      ...migrationContextOf(options.op),
      ...transactionReq(transactionID),
    })
    if (typeof options.updatedAt === 'string' && options.updatedAt !== '') {
      await payload.db.updateOne({
        collection: options.collection,
        id: options.id,
        data: { updatedAt: options.updatedAt },
        returning: false,
        ...transactionReq(transactionID),
      })
    }
  })
}

/**
 * Write host fields through the Local API with the
 * {@link MIGRATION_CONTEXT} marker (`op` names the command) so host
 * hooks can skip outward side effects, letting Payload stamp
 * `updatedAt` as usual — the importer records the captured value and
 * rollback restores it. This is the importer's host pass
 * (`from-payload-auth --apply`); the pre-link keeps the timestamp and
 * goes through {@link updateKeepingTimestamp} instead.
 */
export async function updateHostFields(
  payload: Payload,
  options: {
    readonly collection: string
    readonly id: string | number
    readonly data: Record<string, unknown>
    /** The command this write belongs to (see {@link MIGRATION_CONTEXT}). */
    readonly op: MigrationContextOp
  }
): Promise<void> {
  await payload.update({
    collection: options.collection,
    id: options.id,
    data: options.data,
    overrideAccess: true,
    ...migrationContextOf(options.op),
  })
}

/**
 * Restore every captured field, one adapter write per document so
 * `updatedAt` lands exactly as captured. Returns the number of field
 * values restored. The child-row restore goes through the Local API,
 * so it carries the migration context marker (`op: 'rollback'`) — the
 * same skip key the forward writes carry; the adapter write beside it
 * runs no hooks.
 */
export async function restoreCaptured(
  payload: Payload,
  manifest: Pick<ImportManifest, 'fieldWrites' | 'databaseId' | 'runId'>,
  options: {
    readonly rolesField?: string | undefined
    /** Restore version-1 plaintext values (`--allow-plaintext-restore`). */
    readonly allowPlaintext?: boolean | undefined
    /** The rollback's transaction (see {@link inTransaction}). */
    readonly transactionID?: TransactionId | null | undefined
  } = {}
): Promise<number> {
  const restorable = restorableFieldsFor(options.rolesField ?? 'roles')
  const scope = sealScopeOf(manifest)
  const transaction = () => transactionReq(options.transactionID ?? null)
  const byDoc = new Map<
    string,
    { collection: string; id: string | number; data: Record<string, unknown> }
  >()
  // Every value is opened BEFORE the first write: a value that does
  // not open refuses the whole restore with nothing written.
  for (const write of manifest.fieldWrites) {
    const key = `${write.collection}\u0000${String(write.id)}`
    const entry = byDoc.get(key) ?? { collection: write.collection, id: write.id, data: {} }
    entry.data[write.field] = priorValue(payload.secret, write, restorable, {
      allowPlaintext: options.allowPlaintext,
      scope,
    })
    byDoc.set(key, entry)
  }
  let restored = 0
  for (const entry of byDoc.values()) {
    const fields = payload.collections[entry.collection]?.config.flattenedFields ?? []
    const isChildRowField = (name: string): boolean => {
      const field = fields.find((candidate) => candidate.name === name)
      return (
        field !== undefined &&
        (field.type === 'array' ||
          field.type === 'blocks' ||
          ('hasMany' in field && field.hasMany === true))
      )
    }
    const childRows: Record<string, unknown> = {}
    const columns: Record<string, unknown> = {}
    for (const [field, value] of Object.entries(entry.data)) {
      if (isChildRowField(field)) {
        childRows[field] = value
      } else {
        columns[field] = value
      }
    }
    // Child-row fields (arrays, hasMany) go through the Local API: the
    // SQL adapters rewrite child tables only through a full-document
    // upsert, which the operation provides.
    if (Object.keys(childRows).length > 0) {
      await payload.update({
        collection: entry.collection,
        id: entry.id,
        data: childRows,
        overrideAccess: true,
        ...migrationContextOf('rollback'),
        ...transaction(),
      })
    }
    // Column fields — `updatedAt` LAST-WRITTEN, exactly as captured —
    // go straight through the adapter: a plain UPDATE of just these
    // columns, no fresh timestamp, no hooks.
    if (Object.keys(columns).length > 0) {
      await payload.db.updateOne({
        collection: entry.collection,
        id: entry.id,
        data: columns,
        returning: false,
        ...transaction(),
      })
    }
    restored += Object.keys(entry.data).length
  }
  return restored
}
