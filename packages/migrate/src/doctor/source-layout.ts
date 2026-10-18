import { isRecord } from '@payload-auth-link/core'
import type { SourceModel, SourceTableMap } from '../importer/types.js'

/**
 * The source layout, read off the payload-auth config the doctor
 * already loaded (issue #113). payload-auth stamps every collection it
 * builds with `custom.betterAuthModelKey`, and Payload's SQL adapters
 * name a collection's table after its `dbName`, or its slug in
 * snake_case — so custom slugs (`user-accounts`, `userSessions`) map
 * without a hand-written `--source-map`.
 */

/** payload-auth's model keys → the kit's source models. */
const modelOfKey: Readonly<Record<string, Exclude<SourceModel, 'users_role'>>> = {
  user: 'users',
  account: 'accounts',
  session: 'sessions',
  verification: 'verifications',
  apikey: 'api_keys',
  jwks: 'jwks',
  organization: 'organizations',
  member: 'members',
  invitation: 'invitations',
}

/** Payload's default table name for a slug (the `to-snake-case` rules it uses). */
export function snakeCaseTableName(slug: string): string {
  return slug
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase()
}

/** The collection's table, or `null` when a `dbName` function hides it. */
function tableOf(collection: Record<string, unknown>): string | null {
  const dbName = collection['dbName']
  if (typeof dbName === 'string' && dbName !== '') {
    return dbName
  }
  if (dbName !== undefined) {
    return null
  }
  return typeof collection['slug'] === 'string' ? snakeCaseTableName(collection['slug']) : null
}

/**
 * The model → table map a payload-auth config implies, or `null` when
 * the config carries no payload-auth user collection. Models whose
 * plugin is not installed (no collection) map to `null` — "not
 * installed", exactly what `--source-map` would say. The roles child
 * table is derived only for payload-auth's hasMany `role` select.
 */
export function sourceMapFromConfig(config: unknown): SourceTableMap | null {
  if (!isRecord(config) || !Array.isArray(config['collections'])) {
    return null
  }
  const found = new Map<Exclude<SourceModel, 'users_role'>, string | null>()
  let usersCollection: Record<string, unknown> | null = null
  for (const entry of config['collections'] as unknown[]) {
    if (!isRecord(entry) || !isRecord(entry['custom'])) {
      continue
    }
    const key = entry['custom']['betterAuthModelKey']
    const model = typeof key === 'string' ? modelOfKey[key] : undefined
    if (model === undefined || found.has(model)) {
      continue
    }
    found.set(model, tableOf(entry))
    if (model === 'users') {
      usersCollection = entry
    }
  }
  if (usersCollection === null) {
    return null
  }
  const map: Partial<Record<SourceModel, string | null>> = {}
  for (const model of Object.values(modelOfKey)) {
    const table = found.get(model)
    if (table === undefined) {
      map[model] = null
    } else if (table !== null) {
      map[model] = table
    }
  }
  const usersTable = found.get('users')
  const fields = Array.isArray(usersCollection['fields']) ? usersCollection['fields'] : []
  const role = (fields as unknown[]).find(
    (field): field is Record<string, unknown> => isRecord(field) && field['name'] === 'role'
  )
  if (typeof usersTable === 'string' && role !== undefined && role['hasMany'] === true) {
    map.users_role = `${usersTable}_role`
  }
  return map
}
