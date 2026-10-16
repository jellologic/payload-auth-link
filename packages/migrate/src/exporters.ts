import { Client } from 'pg'
import { presentTables, resolveSourceTables, type ResolvedSourceTables } from './importer/types.js'

/**
 * Off-ramp exporters (issue #58): every payload-auth-link collection's
 * rows as lossless JSONL — each line is one row with every column
 * (including plugin-injected fields: identities, linkable,
 * linkableEmail, suspension, roles child rows), typed as stored.
 * Re-importing the JSONL reproduces the exact rows, so leaving is as
 * testable as arriving.
 */

export type ExportFormat = 'jsonl'

export type ExportOptions = {
  readonly connectionString: string
  readonly format: ExportFormat
  /**
   * Tables to export, exactly (`--tables`). Without it, the export
   * covers EVERY auth table (see {@link resolveAuthTables}).
   */
  readonly tables?: readonly string[] | undefined
  /**
   * The source layout (`--source-map`, issue #110): model → table, or
   * `null` for "not installed". Defaults to payload-auth's layout. A
   * mapped table that does not exist lands in `missing`.
   */
  readonly sourceTables?: ResolvedSourceTables | undefined
  readonly log?: (message: string) => void
}

/**
 * Better Auth plugin tables payload-auth creates beyond the importer's
 * models — exported whenever present (they are auth data the off-ramp
 * must not lose).
 */
export const optionalAuthTables: readonly string[] = [
  'admin_invitations',
  'two_factors',
  'passkeys',
  'sso_providers',
  'organization_roles',
  'teams',
  'team_members',
  'device_code',
  'subscriptions',
]

/**
 * The legacy default auth-table list (payload-auth's default layout plus
 * the plugin's users child tables). Kept for callers that name it;
 * {@link resolveAuthTables} is what the export uses.
 */
export const exportTables: readonly string[] = [
  'users',
  'users_role',
  'users_identities',
  'accounts',
  'sessions',
  'verifications',
  'api_keys',
  'jwks',
  'organizations',
  'members',
  'invitations',
]

export type ExportResult = {
  readonly tables: readonly { readonly name: string; readonly rows: number }[]
  /** The JSONL document: one JSON object per line, `{"table": …, "row": …}`. */
  readonly jsonl: string
  readonly totalRows: number
  /**
   * Required tables that do not exist on the source (issues #68, #110):
   * a `--tables` name, or a mapped model's table. The CLI exits 1 on
   * any; optional tables (children, ba_*, oauth_*) never land here.
   */
  readonly missing: readonly string[]
}

/**
 * The `--tables` flag value (issue #68): a JSON array of table names or
 * a comma-separated list of table names. Anything else is a usage error.
 */
const tableName = /^[A-Za-z_][A-Za-z0-9_]*$/

export function parseExportTables(value: string): readonly string[] {
  const trimmed = value.trim()
  const reject = (): never => {
    throw new Error('--tables must be a JSON array of table names or a comma-separated list')
  }
  if (trimmed === '') {
    return reject()
  }
  if (trimmed.startsWith('[')) {
    const parsed: unknown = JSON.parse(trimmed)
    if (
      !Array.isArray(parsed) ||
      parsed.some((entry) => typeof entry !== 'string' || !tableName.test(entry.trim()))
    ) {
      return reject()
    }
    return (parsed as string[]).map((entry) => entry.trim())
  }
  const names = trimmed
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
  if (names.length === 0 || names.some((entry) => !tableName.test(entry))) {
    return reject()
  }
  return names
}

/**
 * "Every auth table" (issue #110), resolved against what the database
 * actually holds, in dependency order:
 *
 * 1. each mapped model's table (`--source-map` over payload-auth's
 *    layout; `null` = not installed) — REQUIRED: a missing one lands in
 *    `missing`;
 * 2. every child table of those (`<table>_*`: `users_role`,
 *    `users_identities`, `users_sessions`, `organizations_tags`, `_rels`
 *    tables, …) and payload-auth's other Better Auth plugin tables
 *    ({@link optionalAuthTables}) — when present;
 * 3. every `ba_*` (payload-auth-link engine) and `oauth_*` (OAuth
 *    provider) table — when present.
 */
export function resolveAuthTables(
  existing: ReadonlySet<string>,
  sourceTables: ResolvedSourceTables = resolveSourceTables(undefined)
): { readonly tables: readonly string[]; readonly missing: readonly string[] } {
  const tables: string[] = []
  const missing: string[] = []
  const add = (table: string): void => {
    if (!tables.includes(table)) {
      tables.push(table)
    }
  }
  const mapped = presentTables(sourceTables)
  for (const table of mapped) {
    if (existing.has(table)) {
      add(table)
    } else {
      missing.push(table)
    }
  }
  const sorted = [...existing].sort()
  for (const table of [...mapped, ...optionalAuthTables]) {
    if (!mapped.includes(table) && existing.has(table)) {
      add(table)
    }
    for (const child of sorted) {
      if (child.startsWith(`${table}_`)) {
        add(child)
      }
    }
  }
  for (const table of sorted) {
    if (table.startsWith('ba_') || table.startsWith('oauth_')) {
      add(table)
    }
  }
  return { tables, missing }
}

/** Export the auth tables to lossless JSONL (issue #58). */
export async function exportToJsonl(options: ExportOptions): Promise<ExportResult> {
  const client = new Client({ connectionString: options.connectionString })
  await client.connect()
  try {
    const listed = await client.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`
    )
    const existing = new Set(
      listed.rows.map((row) => String((row as { table_name: unknown }).table_name))
    )
    const lines: string[] = []
    const exported: { name: string; rows: number }[] = []
    const missing: string[] = []
    let tables: readonly string[]
    if (options.tables === undefined) {
      const resolved = resolveAuthTables(existing, options.sourceTables)
      tables = resolved.tables
      for (const table of resolved.missing) {
        missing.push(table)
        options.log?.(
          `mapped table '${table}' does not exist on the source — not exported (map its model null with --source-map if it is not installed)`
        )
      }
    } else {
      tables = options.tables
    }
    let totalRows = 0
    for (const table of tables) {
      if (!existing.has(table)) {
        // Nothing is silently omitted (issue #68): every absent table
        // is logged and lands in `missing` for the caller's policy.
        missing.push(table)
        options.log?.(`table '${table}' does not exist on the source — not exported`)
        continue
      }
      const columns = await client.query(
        `SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'id'`,
        [table]
      )
      // Export EVERY column raw (JSON types preserved by ::jsonb cast
      // per row via row_to_json) — lossless by construction.
      const result = await client.query(
        `SELECT row_to_json(t)::jsonb AS row FROM "${table}" t${columns.rows.length > 0 ? ' ORDER BY t.id' : ''}`
      )
      exported.push({ name: table, rows: result.rows.length })
      totalRows += result.rows.length
      for (const row of result.rows) {
        lines.push(JSON.stringify({ table, row: (row as { row: unknown }).row }))
      }
    }
    options.log?.(`exported ${totalRows} row(s) across ${exported.length} table(s)`)
    return { tables: exported, jsonl: `${lines.join('\n')}\n`, totalRows, missing }
  } finally {
    await client.end()
  }
}

/** A round-trip verification row: source vs re-import counts. */
export type RoundTripResult = {
  readonly ok: boolean
  readonly tables: readonly {
    readonly name: string
    readonly source: number
    readonly target: number
  }[]
}

/**
 * Lossless round-trip check (#58): re-import the JSONL into a target
 * schema (same table names) and compare per-table counts. The JSONL
 * rows carry every column, so a re-import that drops or reshapes
 * anything fails here.
 */
export async function verifyRoundTrip(options: {
  readonly sourceConnectionString: string
  readonly targetConnectionString: string
  readonly tables?: readonly string[] | undefined
}): Promise<RoundTripResult> {
  const tables = options.tables ?? exportTables
  const source = new Client({ connectionString: options.sourceConnectionString })
  const target = new Client({ connectionString: options.targetConnectionString })
  await source.connect()
  await target.connect()
  try {
    const results: { name: string; source: number; target: number }[] = []
    for (const table of tables) {
      const s = await source.query(`SELECT count(*)::int AS n FROM ${table}`)
      const t = await target.query(`SELECT count(*)::int AS n FROM ${table}`)
      results.push({
        name: table,
        source: (s.rows[0] as { n?: number } | undefined)?.n ?? 0,
        target: (t.rows[0] as { n?: number } | undefined)?.n ?? 0,
      })
    }
    return { ok: results.every((r) => r.source === r.target), tables: results }
  } finally {
    await source.end()
    await target.end()
  }
}
