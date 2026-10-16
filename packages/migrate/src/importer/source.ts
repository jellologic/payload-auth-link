import { Client } from 'pg'
import {
  defaultSourceTables,
  type ResolvedSourceTables,
  type SourceModel,
  type Unmappable,
} from './types.js'

/**
 * Read side (issue #50): the payload-auth layout, straight from
 * Postgres. Rows are read with plain SELECTs — the source tables are
 * never modified until `finalize` (which only marks the manifest; the
 * drop itself stays the operator's step).
 *
 * Fail closed (issue #68): nothing here tolerates a missing table.
 * `probeSourceLayout` is the gate — the run commands call it first and
 * abort on any finding — so every read below assumes the mapped tables
 * exist and throws if they don't. A customized layout renames tables
 * with `--source-map`, never with silent skips.
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

/** One fail-closed finding: a mapped model's table or column is absent. */
export type SourceLayoutIssue = {
  readonly model: SourceModel
  /** The table (or `table.column`) the probe looked for. */
  readonly key: string
  /** Human reason, naming the table and the `--source-map` escape hatch. */
  readonly reason: string
}

/**
 * The columns each model's reads dereference (issue #68). A layout
 * missing any of these cannot be imported faithfully — the probe
 * blocks on it instead of letting the SELECT fail mid-run (or worse,
 * silently store `undefined`-derived values).
 */
const requiredColumns: Readonly<Record<SourceModel, readonly string[]>> = {
  users: ['id', 'email', 'email_verified'],
  accounts: ['id', 'account_id', 'provider_id', 'user_id'],
  sessions: ['id', 'user_id', 'token', 'expires_at'],
  verifications: ['id', 'identifier', 'value', 'expires_at'],
  api_keys: ['id', 'key', 'reference_id'],
  jwks: ['id', 'public_key', 'private_key'],
  organizations: ['id', 'name', 'slug'],
  members: ['id', 'organization_id', 'user_id'],
  invitations: ['id', 'organization_id', 'email'],
  users_role: ['parent_id', 'value'],
}

/**
 * The slice of a `pg` client the read side uses. Public signatures take
 * this structural type (a `pg.Client` satisfies it) so the published
 * `.d.ts` never references `pg` — consumers need no `@types/pg`.
 */
export interface SourceClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>
  end(): Promise<void>
}

export async function openSource(connectionString: string): Promise<SourceClient> {
  const client = new Client({ connectionString })
  await client.connect()
  return client
}

/** The columns one table actually has (customized layouts drop columns). */
async function columnsOf(client: SourceClient, table: string): Promise<Set<string>> {
  const result = await client.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  )
  return new Set(result.rows.map((row) => String((row as { column_name: unknown }).column_name)))
}

async function tableExists(client: SourceClient, table: string): Promise<boolean> {
  const result = await client.query(
    `SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  )
  return result.rows.length > 0
}

/**
 * Fail-closed probe (issue #68): every mapped model's table must
 * exist (a `null` mapping records "not installed" and is skipped),
 * and every column the reads dereference must be present. The run
 * commands call this FIRST and abort on any finding — nothing is
 * read, planned, or written past a failed probe.
 */
export async function probeSourceLayout(
  client: SourceClient,
  tables: ResolvedSourceTables
): Promise<readonly SourceLayoutIssue[]> {
  const issues: SourceLayoutIssue[] = []
  for (const model of Object.keys(defaultSourceTables) as SourceModel[]) {
    const table = tables[model]
    if (table === null) {
      // Explicitly not installed: skipped by config, never an error.
      continue
    }
    if (!(await tableExists(client, table))) {
      issues.push({
        model,
        key: table,
        reason: `model '${model}' expects source table '${table}', which does not exist — if your layout renamed it, pass --source-map '{"${model}":"<table>"}', or map it null to record it as not installed`,
      })
      continue
    }
    const columns = await columnsOf(client, table)
    for (const column of requiredColumns[model]) {
      if (!columns.has(column)) {
        issues.push({
          model,
          key: `${table}.${column}`,
          reason: `model '${model}' needs column '${column}' on source table '${table}', which does not exist — --source-map maps tables, not columns, so this layout needs a manual review`,
        })
      }
    }
  }
  return issues
}

/**
 * Row counts for the given (mapped, existing) tables. A missing table
 * throws — the probe owns the structured "missing table" report, so a
 * throw here means the probe was skipped.
 */
export async function countTables(
  client: SourceClient,
  tables: readonly string[]
): Promise<Record<string, number>> {
  const counts: Record<string, number> = {}
  for (const table of tables) {
    if (!(await tableExists(client, table))) {
      throw new Error(`source table '${table}' is missing — run probeSourceLayout first`)
    }
    const counted = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
    counts[table] = (counted.rows[0] as { n?: number } | undefined)?.n ?? 0
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
export async function readSourceUsers(
  client: SourceClient,
  tables: ResolvedSourceTables = defaultSourceTables
): Promise<SourceUser[]> {
  const usersTable = tables['users']
  const accountsTable = tables['accounts']
  // A null-mapped model is "not installed" by config: no rows, no read.
  if (usersTable === null) {
    return []
  }
  const users = await client.query(
    `SELECT id, email, name, email_verified, image, created_at, updated_at FROM ${usersTable} ORDER BY id`
  )
  const rolesTable = tables['users_role']
  const roleRows =
    rolesTable === null
      ? { rows: [] as unknown[] }
      : await client.query(`SELECT parent_id, value FROM ${rolesTable} ORDER BY parent_id, "order"`)
  const rolesByUser = new Map<string, string[]>()
  for (const row of roleRows.rows as { parent_id: number; value: string }[]) {
    const list = rolesByUser.get(String(row.parent_id)) ?? []
    list.push(row.value)
    rolesByUser.set(String(row.parent_id), list)
  }
  const accounts =
    accountsTable === null
      ? { rows: [] as unknown[] }
      : await client.query(
          `SELECT id, account_id, provider_id, password, access_token, refresh_token, id_token,
            scope, access_token_expires_at, refresh_token_expires_at, user_id
     FROM ${accountsTable} ORDER BY id`
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

/**
 * Rows of one flat plugin table (sessions, verifications, apiKeys, jwks, …).
 * A missing table throws — a `null` mapping keeps the caller from ever
 * asking for it, and an unmapped missing table aborts at the probe.
 */
export async function readFlatRows(
  client: SourceClient,
  table: string,
  columns: readonly string[]
): Promise<SourceRow[]> {
  if (!(await tableExists(client, table))) {
    throw new Error(`source table '${table}' is missing — run probeSourceLayout first`)
  }
  const result = await client.query(`SELECT ${columns.join(', ')} FROM ${table} ORDER BY id`)
  return result.rows as SourceRow[]
}

/** What the orphan sweep found, and which checks could not run (and why). */
export type OrphanScan = {
  readonly orphans: readonly Unmappable[]
  /** Checks skipped with a reason — reported, never silent (issue #68). */
  readonly skipped: readonly string[]
}

/**
 * Members and invitations reference organizations and users by numeric
 * id; the importer remaps to the target's baIds. Orphaned references
 * are unmappable — they abort the run rather than skip silently.
 *
 * Every check is table-mapped (issue #68). The api-key check probes
 * its columns: better-auth names the owner reference `reference_id`
 * (1.7 / payload-auth layouts) or `user_id` (1.6-era layouts); when
 * neither exists the check is reported as skipped-with-reason instead
 * of passing silently.
 */
export async function findOrphans(
  client: SourceClient,
  tables: ResolvedSourceTables = defaultSourceTables
): Promise<OrphanScan> {
  const orphans: Unmappable[] = []
  const skipped: string[] = []
  const checks: readonly {
    model: string
    table: string | null
    column: string
    target: string | null
  }[] = [
    { model: 'account', table: tables['accounts'], column: 'user_id', target: tables['users'] },
    { model: 'session', table: tables['sessions'], column: 'user_id', target: tables['users'] },
    {
      model: 'member',
      table: tables['members'],
      column: 'organization_id',
      target: tables['organizations'],
    },
    { model: 'member', table: tables['members'], column: 'user_id', target: tables['users'] },
    {
      model: 'invitation',
      table: tables['invitations'],
      column: 'organization_id',
      target: tables['organizations'],
    },
    {
      model: 'invitation',
      table: tables['invitations'],
      column: 'inviter_id',
      target: tables['users'],
    },
  ]
  for (const check of checks) {
    if (check.table === null || check.target === null) {
      // Null-mapped model: not installed by config — an expected skip,
      // recorded so the report says why nothing was checked.
      skipped.push(
        `${check.model}: skipped — ${check.table === null ? 'the model is null-mapped (not installed)' : `its target '${String(check.target)}' is null-mapped (not installed)`}`
      )
      continue
    }
    const exists = await Promise.all([
      tableExists(client, check.table),
      tableExists(client, check.target),
    ])
    if (!exists[0] || !exists[1]) {
      skipped.push(
        `${check.model}: skipped — table '${!exists[0] ? check.table : String(check.target)}' is absent`
      )
      continue
    }
    // Customized layouts drop columns; a missing reference column is
    // reported, not treated as an all-clear.
    if (!(await columnsOf(client, check.table)).has(check.column)) {
      skipped.push(
        `${check.model}: skipped — column '${check.column}' is absent on '${check.table}'`
      )
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

  // api_keys: the owner column is named per layout — probe it.
  const apiKeysTable = tables['api_keys']
  if (apiKeysTable === null) {
    skipped.push('apikey: skipped — the model is null-mapped (not installed)')
  } else if (!(await tableExists(client, apiKeysTable))) {
    skipped.push(`apikey: skipped — table '${apiKeysTable}' is absent`)
  } else {
    const columns = await columnsOf(client, apiKeysTable)
    const column = columns.has('reference_id')
      ? 'reference_id'
      : columns.has('user_id')
        ? 'user_id'
        : null
    const usersTable = tables['users']
    if (column === null) {
      skipped.push(
        `apikey: skipped — neither 'reference_id' nor 'user_id' exists on '${apiKeysTable}'; the owner check cannot run`
      )
    } else if (usersTable === null) {
      skipped.push('apikey: skipped — its target is null-mapped (not installed)')
    } else {
      // The owner column can be varchar (reference_id) or integer
      // (1.6-era user_id): compare through text on both sides so the
      // check runs on either layout.
      const result = await client.query(
        `SELECT t.id FROM ${apiKeysTable} t
         WHERE t.${column} IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM ${usersTable} s WHERE s.id::text = t.${column}::text)`
      )
      for (const row of result.rows as { id: unknown }[]) {
        orphans.push({
          model: 'apikey',
          key: String(row.id),
          reason: `${apiKeysTable}.${column} references a missing ${usersTable} row`,
        })
      }
    }
  }
  return { orphans, skipped }
}

/** Users whose email never verified — reported, never granted `linkable`. */
export function unverifiedEmails(users: readonly SourceUser[]): readonly string[] {
  return users.filter((user) => !user.emailVerified).map((user) => user.email)
}
