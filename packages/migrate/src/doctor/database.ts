import { Client } from 'pg'
import type { DatabaseFinding } from './types.js'

/**
 * Read-only database introspection (issue #52): row counts for the
 * payload-auth layout's auth tables, unverified users (who will not
 * JIT-link), and orphans. Only an honest SELECT — the doctor never
 * writes.
 */

/**
 * The payload-auth 1.9.x Postgres layout (snake_case columns; Payload's
 * drizzle adapter stores hasMany selects as child tables like
 * `users_role`). Tables that don't exist are simply absent from the
 * report — apps customize slugs and drop plugins.
 */
const knownTables: readonly string[] = [
  'users',
  'accounts',
  'sessions',
  'verifications',
  'api_keys',
  'organizations',
  'members',
  'invitations',
  'jwks',
  'admin_invitations',
  'users_role',
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

export async function introspectDatabase(connectionString: string): Promise<DatabaseFinding> {
  const client = new Client({ connectionString })
  await client.connect()
  try {
    const tables: { name: string; rows: number }[] = []
    for (const table of knownTables) {
      if (!(await tableExists(client, table))) {
        continue
      }
      const counted = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
      const first = counted.rows[0] as { n?: number } | undefined
      tables.push({ name: table, rows: first?.n ?? 0 })
    }

    let unverifiedUsers: number | null = null
    if (await tableExists(client, 'users')) {
      const columns = await columnsOf(client, 'users')
      if (columns.has('email_verified')) {
        const counted = await client.query(
          'SELECT count(*)::int AS n FROM users WHERE email_verified = false'
        )
        const first = counted.rows[0] as { n?: number } | undefined
        unverifiedUsers = first?.n ?? null
      }
    }

    const orphans: { kind: string; count: number }[] = []
    const orphanChecks: readonly { kind: string; table: string; column: string; target: string }[] =
      [
        { kind: 'accounts-without-user', table: 'accounts', column: 'user_id', target: 'users' },
        {
          kind: 'members-without-org',
          table: 'members',
          column: 'organization_id',
          target: 'organizations',
        },
        { kind: 'members-without-user', table: 'members', column: 'user_id', target: 'users' },
        {
          kind: 'invitations-without-org',
          table: 'invitations',
          column: 'organization_id',
          target: 'organizations',
        },
      ]
    for (const check of orphanChecks) {
      if (
        (await tableExists(client, check.table)) &&
        (await tableExists(client, check.target)) &&
        (await columnsOf(client, check.table)).has(check.column)
      ) {
        const counted = await client.query(
          `SELECT count(*)::int AS n FROM ${check.table}
           WHERE ${check.column} IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM ${check.target} t WHERE t.id = ${check.table}.${check.column})`
        )
        const first = counted.rows[0] as { n?: number } | undefined
        const count = first?.n ?? 0
        if (count > 0) {
          orphans.push({ kind: check.kind, count })
        }
      }
    }

    return { tables, unverifiedUsers, orphans }
  } finally {
    await client.end()
  }
}
