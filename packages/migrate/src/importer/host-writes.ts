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
 * app.
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

const sealPrefix = 'v1.'

const writeKey = (collection: string, id: string | number, field: string): string =>
  `${collection}\u0000${String(id)}\u0000${field}`

function keyFor(secret: string): Buffer {
  return createHash('sha256')
    .update('payload-auth-link/migrate/manifest-seal/v1\u0000')
    .update(secret)
    .digest()
}

/**
 * Seal one JSON-serialized value under the app's Payload secret. The
 * entry it belongs to (`collection\0id\0field`) is bound as GCM
 * associated data, so a sealed value cannot be moved onto another
 * entry of the manifest.
 */
export function sealValue(secret: string, plaintext: string, entry: string): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', keyFor(secret), iv)
  cipher.setAAD(Buffer.from(entry, 'utf8'))
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${sealPrefix}${Buffer.concat([iv, tag, body]).toString('base64url')}`
}

/** Open a sealed value; throws when the secret is not the sealing one. */
export function unsealValue(secret: string, sealed: string, entry: string): string {
  if (!sealed.startsWith(sealPrefix)) {
    throw new Error('manifest value is not a sealed v1 value')
  }
  const raw = Buffer.from(sealed.slice(sealPrefix.length), 'base64url')
  const iv = raw.subarray(0, 12)
  const tag = raw.subarray(12, 28)
  const body = raw.subarray(28)
  const decipher = createDecipheriv('aes-256-gcm', keyFor(secret), iv)
  decipher.setAuthTag(tag)
  decipher.setAAD(Buffer.from(entry, 'utf8'))
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
  } catch {
    throw new Error(
      'cannot open the manifest: a value was sealed with a different PAYLOAD_SECRET or for a different entry (edited manifest) — run rollback against the same app (same secret) that ran the import, with the manifest it wrote'
    )
  }
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

/** The captured prior value of one manifest entry, JSON-parsed. */
export function priorValue(
  secret: string,
  write: FieldWrite,
  restorable: ReadonlySet<string> = restorableFields
): unknown {
  if (!restorable.has(write.field)) {
    throw new Error(
      `manifest entry for '${write.collection}.${write.field}' is not a field this kit writes; refusing to restore it (edited manifest?)`
    )
  }
  if (write.sealedBefore !== undefined) {
    return JSON.parse(
      unsealValue(secret, write.sealedBefore, writeKey(write.collection, write.id, write.field))
    ) as unknown
  }
  // Version-1 manifests stored the value in the clear.
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
}): Promise<{ readonly present: ReadonlySet<string>; readonly newlyCaptured: number }> {
  const { payload, collection, id, fields, captured, into } = options
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
      sealedBefore: sealValue(payload.secret, JSON.stringify(record[field] ?? null), key),
    })
    newlyCaptured += 1
  }
  return { present, newlyCaptured }
}

/**
 * Restore every captured field, one adapter write per document so
 * `updatedAt` lands exactly as captured. Returns the number of field
 * values restored.
 */
export async function restoreCaptured(
  payload: Payload,
  manifest: Pick<ImportManifest, 'fieldWrites'>,
  options: { readonly rolesField?: string | undefined } = {}
): Promise<number> {
  const restorable = restorableFieldsFor(options.rolesField ?? 'roles')
  const byDoc = new Map<
    string,
    { collection: string; id: string | number; data: Record<string, unknown> }
  >()
  for (const write of manifest.fieldWrites) {
    const key = `${write.collection}\u0000${String(write.id)}`
    const entry = byDoc.get(key) ?? { collection: write.collection, id: write.id, data: {} }
    entry.data[write.field] = priorValue(payload.secret, write, restorable)
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
      })
    }
    restored += Object.keys(entry.data).length
  }
  return restored
}
