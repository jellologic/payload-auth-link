import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { ImportManifest } from './types.js'

/**
 * Manifest integrity (GHSA-p76j-5qwx-rpwx follow-up). Sealing each
 * captured value is not enough: the manifest also says WHICH rows
 * rollback deletes (`created`) and WHICH fields it restores
 * (`fieldWrites`), and both run with `overrideAccess`. A version-3
 * manifest therefore carries an HMAC-SHA256 over its whole body, keyed
 * from the target app's Payload `secret`. Rollback and every resumed
 * `--apply` refuse a manifest whose MAC does not verify, so an edited
 * file can neither delete arbitrary rows nor set arbitrary fields, and
 * a re-run never re-signs an edited file.
 *
 * `finalized` is left out of the MAC: `finalize` is manifest-only and
 * loads no Payload instance (so it has no secret). The flag only ever
 * blocks rollback, and the rows a rollback would touch stay covered.
 */

const macPrefix = 'v1.'

function macKey(secret: string): Buffer {
  return createHash('sha256')
    .update('payload-auth-link/migrate/manifest-mac/v1\u0000')
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

function macOf(secret: string, manifest: ImportManifest): string {
  const body: Record<string, unknown> = { ...manifest }
  delete body['mac']
  delete body['finalized']
  const digest = createHmac('sha256', macKey(secret)).update(canonical(body)).digest()
  return `${macPrefix}${digest.toString('base64url')}`
}

/** Stamp `manifest` as version 3 and sign it under the app's secret. */
export function signManifest(secret: string, manifest: ImportManifest): ImportManifest {
  const unsigned: ImportManifest = { ...manifest, version: 3, mac: undefined }
  return { ...unsigned, mac: macOf(secret, unsigned) }
}

/**
 * Refuse a manifest this app did not write. A version-3 manifest must
 * carry a MAC that verifies under `secret`. A version-1/2 manifest
 * (written before 0.6.0) has no MAC: it is accepted only when the
 * operator passes `allowUnsigned` (`--allow-unsigned-manifest`) to vouch
 * for the file, and even then a version-2 manifest may not hold
 * plaintext values, which that version never wrote.
 */
export function authenticateManifest(
  secret: string,
  manifest: ImportManifest,
  options: { readonly allowUnsigned?: boolean | undefined } = {}
): void {
  if (manifest.version === 3) {
    const expected = Buffer.from(macOf(secret, manifest), 'utf8')
    const actual = Buffer.from(typeof manifest.mac === 'string' ? manifest.mac : '', 'utf8')
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      throw new Error(
        'the manifest failed its integrity check: it was edited, or written by an app with a different PAYLOAD_SECRET. Refusing to use it — run against the same app that wrote it, with the manifest it wrote'
      )
    }
    return
  }
  if (options.allowUnsigned !== true) {
    throw new Error(
      `the manifest is version ${String(manifest.version)} (written before 0.6.0) and carries no integrity check. If you are sure nobody has edited it, re-run with --allow-unsigned-manifest; the next write signs it`
    )
  }
  if (manifest.version === 2 && manifest.fieldWrites.some((write) => write.before !== undefined)) {
    throw new Error(
      'the version-2 manifest holds a plaintext prior value, which version 2 never writes (edited manifest?); refusing to use it'
    )
  }
}
