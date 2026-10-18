import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { ImportManifest } from './types.js'

/**
 * Manifest integrity. Sealing each captured value is not enough: the
 * manifest also says WHICH rows rollback deletes (`created`), WHICH
 * fields it restores (`fieldWrites`), and WHETHER rollback is still
 * allowed (`finalized`), and those writes run with `overrideAccess`. A
 * version-3 manifest therefore carries an HMAC-SHA256 over its whole
 * body, keyed from the target app's Payload `secret`. Rollback, every
 * resumed `--apply`, and `finalize` refuse a manifest whose MAC does
 * not verify, so an edited file can neither delete arbitrary rows, set
 * arbitrary fields, nor reopen a finalized migration — and a re-run
 * never re-signs an edited file.
 *
 * Binding (GHSA-crrr-3cg7-f6jw): a signature proves WHO wrote the file,
 * not WHERE it belongs — a rehearsal database cloned from production
 * shares its secret. A version-4 manifest therefore also carries the
 * target database's id and its run's nonce, both inside the MAC, which
 * `binding.ts` checks against the database's own record. Unsigned and
 * 0.6.0 manifests are never re-signed: they are terminal (rollback or
 * finalize only).
 *
 * Two MAC schemes exist:
 *
 * - `v2.` covers EVERY field, `finalized` included: `finalize` boots
 *   the target app, so it holds the secret and signs its own write.
 * - `v1.` (migrate 0.6.0) left `finalized` out, because `finalize`
 *   then loaded no Payload instance. Such a manifest still verifies —
 *   its rows and field writes are covered — but its `finalized` flag
 *   is not, so it authenticates as `signed-legacy` and destructive
 *   callers gate on that. It is never re-signed (see Binding).
 */

const macPrefix = 'v2.'
const legacyMacPrefix = 'v1.'

type MacScheme = 'v1' | 'v2'

function macKey(secret: string, scheme: MacScheme): Buffer {
  return createHash('sha256')
    .update(`payload-auth-link/migrate/manifest-mac/${scheme}\u0000`)
    .update(secret)
    .digest()
}

/** JSON with object keys sorted at every level (stable across rewrites). */
function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? 'null' : canonical(item))).join(',')}]`
  }
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function macOf(secret: string, manifest: ImportManifest, scheme: MacScheme): string {
  const body: Record<string, unknown> = { ...manifest }
  delete body['mac']
  if (scheme === 'v1') {
    // The 0.6.0 scheme kept `finalized` outside the MAC.
    delete body['finalized']
  }
  const digest = createHmac('sha256', macKey(secret, scheme)).update(canonical(body)).digest()
  return `${scheme === 'v1' ? legacyMacPrefix : macPrefix}${digest.toString('base64url')}`
}

/** A version-4 manifest: signed AND bound to its database and run. */
export type BoundManifest = ImportManifest & {
  readonly version: 4
  readonly databaseId: string
  readonly runId: string
}

/** Whether the manifest carries its (signed) database and run binding. */
export function isBound(manifest: ImportManifest): manifest is BoundManifest {
  return (
    manifest.version === 4 &&
    typeof manifest.databaseId === 'string' &&
    manifest.databaseId !== '' &&
    typeof manifest.runId === 'string' &&
    manifest.runId !== ''
  )
}

/**
 * Sign every field under the app's secret. A manifest that names its
 * database and run is stamped version 4 (GHSA-crrr-3cg7-f6jw); one
 * without (only `finalize` of a 0.7.0 manifest writes that) stays
 * version 3.
 */
export function signManifest(secret: string, manifest: ImportManifest): ImportManifest {
  const bound =
    typeof manifest.databaseId === 'string' &&
    manifest.databaseId !== '' &&
    typeof manifest.runId === 'string' &&
    manifest.runId !== ''
  const unsigned: ImportManifest = { ...manifest, version: bound ? 4 : 3, mac: undefined }
  return { ...unsigned, mac: macOf(secret, unsigned, 'v2') }
}

/**
 * How far a manifest is vouched for:
 *
 * - `signed`: a `v2.` MAC verified; every field, `finalized` included,
 *   is the app's own.
 * - `signed-legacy`: a 0.6.0 `v1.` MAC verified; rows and field writes
 *   are the app's own, `finalized` is NOT covered.
 * - `unsigned`: a version-1/2 manifest (pre-0.6.0) the operator vouched
 *   for with `--allow-unsigned-manifest`; nothing is covered.
 */
export type ManifestTrust = 'signed' | 'signed-legacy' | 'unsigned'

function macMatches(expected: string, actual: string): boolean {
  const want = Buffer.from(expected, 'utf8')
  const got = Buffer.from(actual, 'utf8')
  return got.length === want.length && timingSafeEqual(got, want)
}

/**
 * Refuse a manifest this app did not write. A version-3 manifest must
 * carry a MAC that verifies under `secret`. A version-1/2 manifest
 * (written before 0.6.0) has no MAC: it is accepted only when the
 * operator passes `allowUnsigned` (`--allow-unsigned-manifest`) to vouch
 * for the file, and even then a version-2 manifest may not hold
 * plaintext values, which that version never wrote. Returns how far the
 * manifest is vouched for; destructive callers gate on it.
 */
export function authenticateManifest(
  secret: string,
  manifest: ImportManifest,
  options: { readonly allowUnsigned?: boolean | undefined } = {}
): ManifestTrust {
  if (manifest.version === 4) {
    const mac = typeof manifest.mac === 'string' ? manifest.mac : ''
    if (
      isBound(manifest) &&
      mac.startsWith(macPrefix) &&
      macMatches(macOf(secret, manifest, 'v2'), mac)
    ) {
      return 'signed'
    }
    throw new Error(
      'the manifest failed its integrity check: it was edited, or written by an app with a different PAYLOAD_SECRET. Refusing to use it — run against the same app that wrote it, with the manifest it wrote'
    )
  }
  if (manifest.version === 3) {
    const mac = typeof manifest.mac === 'string' ? manifest.mac : ''
    if (mac.startsWith(macPrefix) && macMatches(macOf(secret, manifest, 'v2'), mac)) {
      return 'signed'
    }
    if (mac.startsWith(legacyMacPrefix) && macMatches(macOf(secret, manifest, 'v1'), mac)) {
      return 'signed-legacy'
    }
    throw new Error(
      'the manifest failed its integrity check: it was edited, or written by an app with a different PAYLOAD_SECRET. Refusing to use it — run against the same app that wrote it, with the manifest it wrote'
    )
  }
  if (options.allowUnsigned !== true) {
    throw new Error(
      `the manifest is version ${String(manifest.version)} (written before 0.6.0) and carries no integrity check. If you are sure nobody has edited it and it was written against THIS database, re-run with --allow-unsigned-manifest; it can then be rolled back or finalized, never resumed or re-signed`
    )
  }
  if (manifest.databaseId !== undefined || manifest.runId !== undefined) {
    throw new Error(
      `the version-${String(manifest.version)} manifest names a database or run, which only a signed version-4 manifest does (edited manifest?); refusing to use it`
    )
  }
  if (manifest.version === 1 && manifest.kind !== undefined && manifest.kind !== 'import') {
    throw new Error(
      `the version-1 manifest claims kind '${String(manifest.kind)}', but version 1 only ever recorded imports (edited manifest?); refusing to use it`
    )
  }
  if (manifest.version === 2 && manifest.fieldWrites.some((write) => write.before !== undefined)) {
    throw new Error(
      'the version-2 manifest holds a plaintext prior value, which version 2 never writes (edited manifest?); refusing to use it'
    )
  }
  return 'unsigned'
}
