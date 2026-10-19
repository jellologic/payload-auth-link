import { Client } from 'pg'
import {
  resolveSourceTables,
  sourceModelNames,
  type ResolvedSourceTables,
} from '../importer/types.js'
import type { DatabaseFinding } from './types.js'

/**
 * Read-only database introspection (issue #52): row counts for the
 * payload-auth layout's auth tables, unverified users (who will not
 * JIT-link), and orphans. Only an honest SELECT — the doctor never
 * writes.
 *
 * Map-aware (issue #68): the ten source models are counted through the
 * `--source-map` (defaulting to payload-auth's layout), and a mapped
 * table that is absent comes back in `missingTables` for the caller to
 * block on — a missing table is never silently reported as 0 rows.
 * Satellite tables beyond the map (two-factor, passkey, sso, …) stay
 * informational: apps drop plugins, and only the mapped models gate.
 */

/** Satellite/extra tables reported when present, never gating. */
const knownTables: readonly string[] = [
  'admin_invitations',
  'two_factors',
  'passkeys',
  'oauth_applications',
  'oauth_access_tokens',
  'oauth_consents',
  'teams',
  'team_members',
  'subscriptions',
  'device_code',
  'sso_providers',
]

async function tableExists(client: Client, table: string): Promise<boolean> {
  const result = await client.query(
    `SELECT 1 FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  )
  return result.rows.length > 0
}

/**
 * Discover the columns a table actually has, so checks adapt to
 * customized layouts instead of assuming.
 */
async function columnsOf(client: Client, table: string): Promise<Set<string>> {
  const result = await client.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  )
  return new Set(result.rows.map((row) => String((row as { column_name: unknown }).column_name)))
}

export type IntrospectOptions = {
  /** Model → source table map (`--source-map`); defaults to the default layout. */
  readonly sourceTables?: Readonly<Record<string, string | null>> | undefined
}

export async function introspectDatabase(
  connectionString: string,
  options: IntrospectOptions = {}
): Promise<DatabaseFinding> {
  const tables: ResolvedSourceTables = resolveSourceTables(options.sourceTables)
  const client = new Client({ connectionString })
  await client.connect()
  try {
    const counted: { name: string; rows: number }[] = []
    const missing: { model: string; table: string }[] = []

    // The mapped models count, and a missing mapped table is reported
    // for the caller to block on (issue #68).
    for (const model of sourceModelNames) {
      const table = tables[model]
      if (table === null) {
        continue
      }
      if (!(await tableExists(client, table))) {
        missing.push({ model, table })
        continue
      }
      const result = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
      const first = result.rows[0] as { n?: number } | undefined
      counted.push({ name: table, rows: first?.n ?? 0 })
    }

    // Satellite tables: informational when present.
    for (const table of knownTables) {
      if (!(await tableExists(client, table))) {
        continue
      }
      const result = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
      const first = result.rows[0] as { n?: number } | undefined
      counted.push({ name: table, rows: first?.n ?? 0 })
    }

    let unverifiedUsers: number | null = null
    let bannedUsers: number | null = null
    let anonymousUsers: number | null = null
    const usersTable = tables['users']
    if (usersTable !== null && (await tableExists(client, usersTable))) {
      const columns = await columnsOf(client, usersTable)
      const countWhere = async (predicate: string): Promise<number | null> => {
        const result = await client.query(
          `SELECT count(*)::int AS n FROM ${usersTable} WHERE ${predicate}`
        )
        const first = result.rows[0] as { n?: number } | undefined
        return first?.n ?? null
      }
      if (columns.has('email_verified')) {
        unverifiedUsers = await countWhere('email_verified = false')
      }
      // Better Auth plugin state the import must carry (issue #88).
      if (columns.has('banned')) {
        bannedUsers = await countWhere('banned = true')
      }
      if (columns.has('is_anonymous')) {
        anonymousUsers = await countWhere('is_anonymous = true')
      }
    }

    // OAuth-provider plugin tables (oauthProvider / oidcProvider /
    // mcp): the importer does not carry them (issue #88).
    const oauthResult = await client.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name LIKE 'oauth\\_%'
       ORDER BY table_name`
    )
    const oauthTables = oauthResult.rows.map((row) =>
      String((row as { table_name: unknown }).table_name)
    )

    // Payload's key-value store backs the migration's own records (the
    // database identity, its runs, the finalize marker). A database
    // whose app never ran the Payload migration creating it fails every
    // --apply; report its presence so the doctor can flag the gap
    // before that.
    const payloadKvTable = await tableExists(client, 'payload_kv')
    const migrationRecordsTable = await tableExists(client, 'payload_auth_link_migrations')

    const orphans: { kind: string; count: number }[] = []
    const skippedChecks: string[] = []
    const orphanChecks: readonly {
      kind: string
      table: string | null
      column: string
      target: string | null
    }[] = [
      {
        kind: 'accounts-without-user',
        table: tables['accounts'],
        column: 'user_id',
        target: usersTable,
      },
      {
        kind: 'members-without-org',
        table: tables['members'],
        column: 'organization_id',
        target: tables['organizations'],
      },
      {
        kind: 'members-without-user',
        table: tables['members'],
        column: 'user_id',
        target: usersTable,
      },
      {
        kind: 'invitations-without-org',
        table: tables['invitations'],
        column: 'organization_id',
        target: tables['organizations'],
      },
    ]
    for (const check of orphanChecks) {
      if (check.table === null || check.target === null) {
        skippedChecks.push(`${check.kind}: skipped — a mapped model is null-mapped (not installed)`)
        continue
      }
      if (
        (await tableExists(client, check.table)) &&
        (await tableExists(client, check.target)) &&
        (await columnsOf(client, check.table)).has(check.column)
      ) {
        const result = await client.query(
          `SELECT count(*)::int AS n FROM ${check.table}
           WHERE ${check.column} IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM ${check.target} t WHERE t.id = ${check.table}.${check.column})`
        )
        const first = result.rows[0] as { n?: number } | undefined
        const count = first?.n ?? 0
        if (count > 0) {
          orphans.push({ kind: check.kind, count })
        }
      } else {
        skippedChecks.push(`${check.kind}: skipped — a table or column involved is absent`)
      }
    }

    // api keys: the owner column is named per layout — probe it
    // (issue #68: `reference_id` on current layouts, `user_id` on 1.6).
    const apiKeysTable = tables['api_keys']
    if (apiKeysTable === null) {
      skippedChecks.push('api-keys-without-user: skipped — the model is null-mapped')
    } else if (!(await tableExists(client, apiKeysTable))) {
      if (!missing.some((entry) => entry.model === 'api_keys')) {
        skippedChecks.push(`api-keys-without-user: skipped — table '${apiKeysTable}' is absent`)
      }
    } else {
      const columns = await columnsOf(client, apiKeysTable)
      const column = columns.has('reference_id')
        ? 'reference_id'
        : columns.has('user_id')
          ? 'user_id'
          : null
      if (column === null || usersTable === null) {
        skippedChecks.push(
          `api-keys-without-user: skipped — neither 'reference_id' nor 'user_id' exists on '${apiKeysTable}'`
        )
      } else {
        // Text casts on both sides: the owner column may be varchar
        // (reference_id) or integer (1.6-era user_id).
        const result = await client.query(
          `SELECT count(*)::int AS n FROM ${apiKeysTable}
           WHERE ${column} IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM ${usersTable} t WHERE t.id::text = ${apiKeysTable}.${column}::text)`
        )
        const first = result.rows[0] as { n?: number } | undefined
        const count = first?.n ?? 0
        if (count > 0) {
          orphans.push({ kind: 'api-keys-without-user', count })
        }
      }
    }

    return {
      tables: counted,
      unverifiedUsers,
      orphans,
      missingTables: missing,
      skippedChecks,
      bannedUsers,
      anonymousUsers,
      oauthTables,
      payloadKvTable,
      migrationRecordsTable,
    }
  } finally {
    await client.end()
  }
}
