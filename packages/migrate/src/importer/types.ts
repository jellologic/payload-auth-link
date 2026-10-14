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
