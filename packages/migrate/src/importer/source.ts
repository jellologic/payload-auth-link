import { Client } from 'pg'
import type { Unmappable } from './types.js'

/**
 * Read side (issue #50): the payload-auth layout, straight from
 * Postgres. Rows are read with plain SELECTs — the source tables are
 * never modified until `finalize` (which only marks the manifest; the
 * drop itself stays the operator's step).
 */

/** One payload-auth source user with its role rows and accounts. */
export type SourceUser = {
  readonly id: string
  readonly email: string
  readonly name: string | null
  readonly emailVerified: boolean
  readonly image: string | null
  readonly createdAt: Date
  readonly updatedAt: Date
  /** Stored role values from the `users_role` child table. */
  readonly roles: readonly string[]
  readonly accounts: readonly SourceAccount[]
}

export type SourceAccount = {
  readonly id: string
  readonly accountId: string
  readonly providerId: string
  readonly password: string | null
  readonly accessToken: string | null
  readonly refreshToken: string | null
  readonly idToken: string | null
  readonly scope: string | null
  readonly accessTokenExpiresAt: Date | null
  readonly refreshTokenExpiresAt: Date | null
}

export type SourceRow = Record<string, unknown>

export async function openSource(connectionString: string): Promise<Client> {
  const client = new Client({ connectionString })
  await client.connect()
  return client
}

/** The columns one table actually has (customized layouts drop columns). */
async function columnsOf(client: Client, table: string): Promise<Set<string>> {
  const result = await client.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  )
  return new Set(result.rows.map((row) => String((row as { column_name: unknown }).column_name)))
}

async function tableExists(client: Client, table: string): Promise<boolean> {
  const result = await client.query(
    `SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  )
  return result.rows.length > 0
}

export async function countTables(
  client: Client,
  tables: readonly string[]
): Promise<Record<string, number>> {
  const counts: Record<string, number> = {}
  for (const table of tables) {
    if (await tableExists(client, table)) {
      const counted = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
      counts[table] = (counted.rows[0] as { n?: number } | undefined)?.n ?? 0
    } else {
      counts[table] = 0
    }
  }
  return counts
}

function iso(value: unknown): Date | null {
  return value instanceof Date ? value : null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

/** Every source user, with role rows and accounts attached. */
export async function readSourceUsers(client: Client): Promise<SourceUser[]> {
  const hasRoleTable = await tableExists(client, 'users_role')
  const users = await client.query(
    `SELECT id, email, name, email_verified, image, created_at, updated_at FROM users ORDER BY id`
  )
  const roleRows = hasRoleTable
    ? await client.query(`SELECT parent_id, value FROM users_role ORDER BY parent_id, "order"`)
    : { rows: [] as unknown[] }
  const rolesByUser = new Map<string, string[]>()
  for (const row of roleRows.rows as { parent_id: number; value: string }[]) {
    const list = rolesByUser.get(String(row.parent_id)) ?? []
    list.push(row.value)
    rolesByUser.set(String(row.parent_id), list)
  }
  const accounts = await client.query(
    `SELECT id, account_id, provider_id, password, access_token, refresh_token, id_token,
            scope, access_token_expires_at, refresh_token_expires_at, user_id
     FROM accounts ORDER BY id`
  )
  const accountsByUser = new Map<string, SourceAccount[]>()
  for (const row of accounts.rows as Record<string, unknown>[]) {
    const userId = String(row.user_id)
    const account: SourceAccount = {
      id: String(row.id),
      accountId: String(row.account_id),
      providerId: String(row.provider_id),
      password: text(row.password),
      accessToken: text(row.access_token),
      refreshToken: text(row.refresh_token),
      idToken: text(row.id_token),
      scope: text(row.scope),
      accessTokenExpiresAt: iso(row.access_token_expires_at),
      refreshTokenExpiresAt: iso(row.refresh_token_expires_at),
    }
    const list = accountsByUser.get(userId) ?? []
    list.push(account)
    accountsByUser.set(userId, list)
  }
  const out: SourceUser[] = []
  for (const row of users.rows as Record<string, unknown>[]) {
    const id = String(row.id)
    out.push({
      id,
      email: String(row.email),
      name: text(row.name),
      emailVerified: row.email_verified === true,
      image: text(row.image),
      createdAt: iso(row.created_at) ?? new Date(),
      updatedAt: iso(row.updated_at) ?? new Date(),
      roles: rolesByUser.get(id) ?? [],
      accounts: accountsByUser.get(id) ?? [],
    })
  }
  return out
}

/** Rows of one flat plugin table (sessions, verifications, apiKeys, jwks, …). */
export async function readFlatRows(
  client: Client,
  table: string,
  columns: readonly string[]
): Promise<SourceRow[]> {
  if (!(await tableExists(client, table))) {
    return []
  }
  const result = await client.query(`SELECT ${columns.join(', ')} FROM ${table} ORDER BY id`)
  return result.rows as SourceRow[]
}

/**
 * Members and invitations reference organizations and users by numeric
 * id; the importer remaps to the target's baIds. Orphaned references
 * are unmappable — they abort the run rather than skip silently.
 */
export async function findOrphans(client: Client): Promise<readonly Unmappable[]> {
  const orphans: Unmappable[] = []
  const checks: readonly { model: string; table: string; column: string; target: string }[] = [
    { model: 'account', table: 'accounts', column: 'user_id', target: 'users' },
    { model: 'session', table: 'sessions', column: 'user_id', target: 'users' },
    { model: 'member', table: 'members', column: 'organization_id', target: 'organizations' },
    { model: 'member', table: 'members', column: 'user_id', target: 'users' },
    {
      model: 'invitation',
      table: 'invitations',
      column: 'organization_id',
      target: 'organizations',
    },
    { model: 'invitation', table: 'invitations', column: 'inviter_id', target: 'users' },
    { model: 'apikey', table: 'api_keys', column: 'user_id', target: 'users' },
  ]
  for (const check of checks) {
    const exists = await Promise.all([
      tableExists(client, check.table),
      tableExists(client, check.target),
    ])
    if (!exists[0] || !exists[1]) {
      continue
    }
    // Customized layouts drop columns; a missing reference column is
    // not an orphan farm.
    if (!(await columnsOf(client, check.table)).has(check.column)) {
      continue
    }
    const result = await client.query(
      `SELECT t.id FROM ${check.table} t
       WHERE t.${check.column} IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM ${check.target} s WHERE s.id = t.${check.column})`
    )
    for (const row of result.rows as { id: unknown }[]) {
      orphans.push({
        model: check.model,
        key: String(row.id),
        reason: `${check.table}.${check.column} references a missing ${check.target} row`,
      })
    }
  }
  return orphans
}

/** Users whose email never verified — reported, never granted `linkable`. */
export function unverifiedEmails(users: readonly SourceUser[]): readonly string[] {
  return users.filter((user) => !user.emailVerified).map((user) => user.email)
}
