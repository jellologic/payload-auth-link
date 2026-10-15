/**
 * Importer manifest (issue #50): every row created and every field
 * changed, so `rollback` is exact. The manifest is the run's contract —
 * `verify`, `rollback`, and `finalize` all read it.
 */
export type CreatedRow = {
  /** Target collection slug. */
  readonly collection: string
  /** Payload document id of the created row. */
  readonly id: string | number
  /** The source identity this row was created for (dedupe on resume). */
  readonly sourceKey: string
}

export type FieldWrite = {
  readonly collection: string
  readonly id: string | number
  readonly field: string
  /** The prior value, JSON-serialized, restored by rollback. */
  readonly before: string | null
}

export type ImportManifest = {
  readonly version: 1
  readonly createdAt: string
  readonly sourceDatabase: string
  readonly options: {
    readonly sessions: 'carry' | 'drop'
  }
  readonly created: CreatedRow[]
  readonly fieldWrites: FieldWrite[]
  readonly finalized: boolean
  /** Counts per source table at plan time (the rollback baseline). */
  readonly sourceCounts: Readonly<Record<string, number>>
  /** Cumulative plan totals (rows created + skipped across resumes). */
  readonly totals: Readonly<Record<string, number>>
}

/** Per-model plan row for the dry run. */
export type PlanRow = {
  readonly model: string
  readonly sourceTable: string
  readonly targetCollection: string
  readonly rows: number
  readonly skipped: number
  readonly unmappable: readonly string[]
}

/** Why a row cannot be imported — the run aborts rather than skips. */
export type Unmappable = {
  readonly model: string
  readonly key: string
  readonly reason: string
}

export type ImportPlan = {
  readonly rows: readonly PlanRow[]
  readonly unmappable: readonly Unmappable[]
  readonly sessions: 'carry' | 'drop'
  readonly warnings: readonly string[]
}

export type ImportResult = {
  readonly created: number
  readonly skipped: number
  readonly fieldWrites: number
  readonly plan: ImportPlan
}

/**
 * The models the source side names (issue #68). One entry per
 * payload-auth table the importer/doctor reads — the keys are stable
 * model names; the values are whatever the source database actually
 * called the table.
 */
export type SourceModel =
  | 'users'
  | 'accounts'
  | 'sessions'
  | 'verifications'
  | 'api_keys'
  | 'jwks'
  | 'organizations'
  | 'members'
  | 'invitations'
  | 'users_role'

/**
 * A model → source-table override for custom layouts (`--source-map`):
 * `{"accounts":"user_accounts","sessions":"user_sessions"}`. A `null`
 * value means the model is explicitly NOT installed on the source
 * (recorded as skipped-by-config, never probed as an error).
 */
export type SourceTableMap = { readonly [M in SourceModel]?: string | null }

/** Every model resolved to its source table (`null` = not installed). */
export type ResolvedSourceTables = Readonly<Record<SourceModel, string | null>>

/** payload-auth's default Postgres layout. */
export const defaultSourceTables: Readonly<Record<SourceModel, string>> = {
  users: 'users',
  accounts: 'accounts',
  sessions: 'sessions',
  verifications: 'verifications',
  api_keys: 'api_keys',
  jwks: 'jwks',
  organizations: 'organizations',
  members: 'members',
  invitations: 'invitations',
  users_role: 'users_role',
}

/** All known source models — the error message names them. */
export const sourceModelNames: readonly SourceModel[] = Object.keys(
  defaultSourceTables
) as SourceModel[]

/**
 * Parse the `--source-map` JSON (same boundary style as `--slugs`):
 * keys must be known source models, values a table name or `null`
 * ("model not installed"). Unknown keys throw — a typo would
 * otherwise silently skip the model it meant to map.
 */
export function parseSourceMapJson(json: string): SourceTableMap {
  const parsed: unknown = JSON.parse(json)
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('--source-map must be a JSON object of model -> table name (or null)')
  }
  const map: Record<string, string | null> = {}
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!sourceModelNames.includes(key as SourceModel)) {
      throw new Error(
        `--source-map has an unknown model '${key}'; the known models are: ${sourceModelNames.join(', ')}`
      )
    }
    if (value !== null && (typeof value !== 'string' || value.trim() === '')) {
      throw new Error(`--source-map['${key}'] must be a table name or null`)
    }
    map[key] = value === null ? null : value.trim()
  }
  return map
}

/** Merge `--source-map` overrides onto the default layout. */
export function resolveSourceTables(map: SourceTableMap | undefined): ResolvedSourceTables {
  return { ...defaultSourceTables, ...(map ?? {}) }
}

/** The tables to read (the mapped ones — `null` entries are skipped). */
export function presentTables(tables: ResolvedSourceTables): readonly string[] {
  return sourceModelNames
    .map((model) => tables[model])
    .filter((table): table is string => table !== null)
}

/** The models the importer copies. */
export type TargetModel =
  | 'user'
  | 'session'
  | 'account'
  | 'verification'
  | 'apikey'
  | 'jwks'
  | 'organization'
  | 'member'
  | 'invitation'

/** Target slugs with the known models always present (index-safe). */
export type TargetSlugMap = Record<TargetModel, string> & Record<string, string>

/** Default target slugs; must match the app's engine wiring. */
export const defaultTargetSlugs: TargetSlugMap = {
  user: 'ba-users',
  session: 'ba-sessions',
  account: 'ba-accounts',
  verification: 'ba-verifications',
  apikey: 'ba-apikey',
  jwks: 'ba-jwks',
  organization: 'ba-organization',
  member: 'ba-member',
  invitation: 'ba-invitation',
}
