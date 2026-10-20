import { isRecord } from '@payload-auth-link/core'
import type { DoctorIssue } from './types.js'

/**
 * Readable credential fields on ADOPTED provider collections (issue
 * #145): adopt mode reuses the host's payload-auth-built collections
 * (accounts, sessions, verifications, api_keys) WITH their legacy
 * access rules — often a collection-level `read` like adminOrSelf with
 * NO field-level read, so a signed-in user can read their own password
 * hash and OAuth tokens over REST/GraphQL. Static config analysis (no
 * database): the doctor is the review moment before the cutover.
 *
 * The check cannot know what an access FUNCTION returns, so it flags
 * every credential field without a field-level `access.read` unless
 * the collection-level read is LITERALLY `() => false` — the one shape
 * it can prove denies everyone (`denyAllAccess()` in
 * `@payload-auth-link/core` emits exactly that). A field that declares
 * its own `access.read` is the host's decision and stays silent.
 */

/** Credential field names per Better Auth model key; camelCase first. */
const credentialFieldsByModel: Readonly<Record<string, readonly string[]>> = {
  account: ['password', 'accessToken', 'refreshToken', 'refresh_token', 'idToken', 'id_token'],
  session: ['token'],
  verification: ['value'],
  apikey: ['key'],
}

/** Human name of each mapped model, for the warning detail. */
const modelLabels: Readonly<Record<string, string>> = {
  account: 'Better Auth accounts',
  session: 'Better Auth sessions',
  verification: 'Better Auth verifications',
  apikey: 'Better Auth API keys',
}

/**
 * The access function is literally `() => false` (or its long
 * `function` form) — deny-everyone, provably. Anything else is opaque
 * and treated as potentially granting the read.
 */
export function isDenyAllRead(read: unknown): boolean {
  if (typeof read !== 'function') {
    return false
  }
  const source = read.toString().replace(/\s+/g, ' ').trim()
  return source === '() => false' || source === 'function () { return false }'
}

/** Named fields of a collection, including those nested in tabs/groups. */
function namedFields(fields: unknown, into: Map<string, Record<string, unknown>>): void {
  if (!Array.isArray(fields)) {
    return
  }
  for (const field of fields) {
    if (!isRecord(field)) {
      continue
    }
    if (typeof field['name'] === 'string' && typeof field['type'] === 'string') {
      into.set(field['name'], field)
    }
    namedFields(field['fields'], into)
    const tabs = field['tabs']
    if (Array.isArray(tabs)) {
      for (const tab of tabs) {
        if (isRecord(tab)) {
          namedFields(tab['fields'], into)
        }
      }
    }
  }
}

/**
 * One warning per credential field on an adopted provider collection
 * (payload-auth stamps each with `custom.betterAuthModelKey`) that a
 * non-manager can read: no field-level `access.read`, and the
 * collection-level read is not literally `() => false`.
 */
export function readableCredentialFields(config: unknown): DoctorIssue[] {
  if (!isRecord(config) || !Array.isArray(config['collections'])) {
    return []
  }
  const issues: DoctorIssue[] = []
  for (const entry of config['collections']) {
    if (!isRecord(entry)) {
      continue
    }
    const slug = entry['slug']
    if (typeof slug !== 'string') {
      continue
    }
    const custom = entry['custom']
    const model =
      isRecord(custom) && typeof custom['betterAuthModelKey'] === 'string'
        ? custom['betterAuthModelKey']
        : null
    if (model === null) {
      continue
    }
    const credentialFields = credentialFieldsByModel[model]
    if (credentialFields === undefined) {
      continue
    }
    const access = entry['access']
    const collectionRead = isRecord(access) ? access['read'] : undefined
    // Batch-skip: the one collection-level read the doctor can PROVE
    // denies everyone closes every field at once.
    if (isDenyAllRead(collectionRead)) {
      continue
    }
    const readShape =
      collectionRead === undefined
        ? "the collection declares no read access, so Payload's default (any signed-in user may read) applies"
        : 'the collection-level read does not deny everyone (an adminOrSelf-style read already lets a signed-in user read their OWN row)'
    const fields = new Map<string, Record<string, unknown>>()
    namedFields(entry['fields'], fields)
    for (const name of credentialFields) {
      const field = fields.get(name)
      if (
        field === undefined ||
        (isRecord(field['access']) && field['access']['read'] !== undefined)
      ) {
        continue
      }
      issues.push({
        code: 'readable-credential-field',
        detail: `the adopted '${slug}' collection (${
          modelLabels[model] ?? model
        }) lets a non-manager read the credential field '${name}': the field declares no access.read, and ${readShape} — over REST/GraphQL that returns the stored secret. Give the field managers-only read access (access: { read: <managers only> }) or deny it outright; the engine's own ba-* collections default to denyAllAccess() (@payload-auth-link/core), and the adapter's writes are unaffected (overrideAccess). See docs/migrating-from-payload-auth.md, "Adopt mode"`,
      })
    }
  }
  return issues
}
