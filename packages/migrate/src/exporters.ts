import { Client } from 'pg'

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
  /** Tables to export; defaults to the full auth-table set. */
  readonly tables?: readonly string[] | undefined
  readonly log?: (message: string) => void
}

/** The auth-table set, in dependency order for re-import. */
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
   * Requested tables that do not exist on the source (issue #68). The
   * caller decides policy: `--tables` names must abort (exit 1),
   * default-list gaps are reported but tolerated.
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

/** Export the auth tables to lossless JSONL (issue #58). */
export async function exportToJsonl(options: ExportOptions): Promise<ExportResult> {
  const tables = options.tables ?? exportTables
  const client = new Client({ connectionString: options.connectionString })
  await client.connect()
  try {
    const lines: string[] = []
    const exported: { name: string; rows: number }[] = []
    const missing: string[] = []
    let totalRows = 0
    for (const table of tables) {
      const exists = await client.query(
        `SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`,
        [table]
      )
      if (exists.rows.length === 0) {
        // Nothing is silently omitted (issue #68): every absent table
        // is logged and lands in `missing` for the caller's policy.
        missing.push(table)
        options.log?.(`table '${table}' does not exist on the source — not exported`)
        continue
      }
      // Export EVERY column raw (JSON types preserved by ::jsonb cast
      // per row via row_to_json) — lossless by construction.
      const result = await client.query(
        `SELECT row_to_json(t)::jsonb AS row FROM ${table} t ORDER BY t.id`
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
