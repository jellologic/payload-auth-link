import type { SourceTableMap } from '../importer/types.js'

/**
 * The doctor's report shape (issue #52): read-only findings, every
 * one carrying a stable machine code so tests (and the guide) assert
 * exact blocker lists instead of prose.
 */

/** A finding the doctor is confident about: fix it before migrating. */
export type DoctorIssue = {
  /** Stable machine code — e.g. `better-auth-out-of-band`. */
  readonly code: string
  /** Human detail: what was found, what closes it. */
  readonly detail: string
}

/** One upstream dependency against its supported band. */
export type VersionFinding = {
  readonly name: string
  /** `null` when no manifest resolved (exotic bundling). */
  readonly installed: string | null
  /** The supported band, human-readable. */
  readonly band: string
  readonly status: 'ok' | 'warning' | 'blocker' | 'unknown'
  readonly detail: string
}

/** One Better Auth plugin's migration posture. */
export type PluginFinding = {
  /** The plugin's `id` (or the satellite package name). */
  readonly id: string
  readonly status: 'supported' | 'auto-declarable' | 'unprobed' | 'unsupported' | 'removed-upstream'
  readonly detail: string
  /** Files under `--src` whose source names this plugin (issue #71). */
  readonly files?: readonly string[]
}

/** The users collection, as the migration will meet it. */
export type UsersFinding = {
  /** Collection slug (payload-auth's `users` by default). */
  readonly slug: string
  readonly roleField: {
    readonly name: string
    readonly type: string
    readonly hasMany: boolean
    /** Declared select values, when the field is a select. */
    readonly values: readonly string[]
    /** Values that are not canonical lowercase slugs. */
    readonly nonCanonical: readonly string[]
  } | null
  /** Payload's own email+password local strategy is active. */
  readonly localStrategy: boolean
  /** Host fields colliding with the plugin's injected field names. */
  readonly collisions: readonly string[]
  readonly notes: readonly string[]
}

/** One source-scan category with the files that matched. */
export type SourceFinding = {
  readonly kind:
    | 'payload-auth-import'
    | 'better-auth-accessor'
    | 'get-payload-auth'
    | 'ba-internals'
    | 'req-user-field'
  readonly files: readonly string[]
  /** For `req-user-field`: every field read off `req.user`. */
  readonly fields: readonly string[]
  readonly detail: string
}

/** Database state, as far as a read-only connection can see. */
export type DatabaseFinding = {
  readonly tables: readonly { readonly name: string; readonly rows: number }[]
  /** Users with `emailVerified = false` — imported pre-linked, but without the verified-email linking proof. */
  readonly unverifiedUsers: number | null
  readonly orphans: readonly { readonly kind: string; readonly count: number }[]
  /**
   * Mapped source models whose table is absent (issue #68) — blockers
   * unless `--source-map` records the model as not installed.
   */
  readonly missingTables?: readonly { readonly model: string; readonly table: string }[]
  /** Orphan checks that could not run, with the reason (issue #68). */
  readonly skippedChecks?: readonly string[]
  /**
   * Users banned by Better Auth's admin plugin (`banned = true`), or
   * `null` when the source has no `banned` column (issue #88).
   */
  readonly bannedUsers?: number | null
  /** Anonymous-plugin users (`is_anonymous = true`), or `null` (issue #88). */
  readonly anonymousUsers?: number | null
  /**
   * OAuth-provider plugin tables present (`oauth_*`, issue #88). The
   * importer does NOT carry them; the doctor says so explicitly.
   */
  readonly oauthTables?: readonly string[]
  /**
   * Whether Payload's key-value store table (`payload_kv`) exists. The
   * migration records its database identity, runs, and finalize marker
   * there, so a target database without the table refuses every
   * `--apply`.
   */
  readonly payloadKvTable?: boolean
}

/** Default-behaviour changes in payload-auth-link 0.7.0 that bite. */
export type BehaviourChange = {
  readonly title: string
  readonly detail: string
}

/** The full read-only doctor report (`--json` prints this object). */
export type DoctorReport = {
  readonly versions: readonly VersionFinding[]
  readonly plugins: readonly PluginFinding[]
  readonly users: UsersFinding | null
  readonly source: readonly SourceFinding[]
  readonly database: DatabaseFinding | null
  /**
   * The source layout derived from the loaded payload-auth config
   * (issue #113): model → table, `null` for a model whose plugin is
   * not installed. Pass it to the importer, `verify`, and `export` as
   * `--source-map`. Absent when the config is not a payload-auth one.
   */
  readonly sourceMap?: SourceTableMap
  readonly behaviourChanges: readonly BehaviourChange[]
  readonly blockers: readonly DoctorIssue[]
  readonly warnings: readonly DoctorIssue[]
}
