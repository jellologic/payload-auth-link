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
  /**
   * Better Auth admin-plugin ban state (issue #88), `null` when the
   * source layout has no such column (the plugin was never installed).
   */
  readonly banned: boolean | null
  readonly banReason: string | null
  readonly banExpires: Date | null
  /** Better Auth anonymous-plugin marker; `null` when no column exists. */
  readonly isAnonymous: boolean | null
}

export type SourceAccount = {
  readonly id: string
  /** Source row timestamps, carried onto the target row (issue #88). */
  readonly createdAt: Date | null
  readonly updatedAt: Date | null
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

/**
 * Fail-closed probe (issue #68): every mapped model's table must
 * exist (a `null` mapping records "not installed" and is skipped),
 * and every column the reads dereference must be present. The run
 * commands call this FIRST and abort on any finding — nothing is
 * read, planned, or written past a failed probe.
 */
export async function probeSourceLayout(
  client: Client,
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
  client: Client,
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
  client: Client,
  tables: ResolvedSourceTables = defaultSourceTables
): Promise<SourceUser[]> {
  const usersTable = tables['users']
  const accountsTable = tables['accounts']
  // A null-mapped model is "not installed" by config: no rows, no read.
  if (usersTable === null) {
    return []
  }
  // Plugin columns (admin bans, anonymous marker) exist only when the
  // payload-auth app installed those plugins — read them when present.
  const userColumns = await columnsOf(client, usersTable)
  const optionalUserColumns = ['banned', 'ban_reason', 'ban_expires', 'is_anonymous'].filter(
    (column) => userColumns.has(column)
  )
  const users = await client.query(
    `SELECT ${['id', 'email', 'name', 'email_verified', 'image', 'created_at', 'updated_at', ...optionalUserColumns].join(', ')} FROM ${usersTable} ORDER BY id`
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
  const accountColumns =
    accountsTable === null ? new Set<string>() : await columnsOf(client, accountsTable)
  const accountTimestamps = ['created_at', 'updated_at'].filter((column) =>
    accountColumns.has(column)
  )
  const accounts =
    accountsTable === null
      ? { rows: [] as unknown[] }
      : await client.query(
          `SELECT ${[
            'id',
            'account_id',
            'provider_id',
            'password',
            'access_token',
            'refresh_token',
            'id_token',
            'scope',
            'access_token_expires_at',
            'refresh_token_expires_at',
            'user_id',
            ...accountTimestamps,
          ].join(', ')} FROM ${accountsTable} ORDER BY id`
        )
  const accountsByUser = new Map<string, SourceAccount[]>()
  for (const row of accounts.rows as Record<string, unknown>[]) {
    const userId = String(row.user_id)
    const account: SourceAccount = {
      id: String(row.id),
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
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
      banned: userColumns.has('banned') ? row.banned === true : null,
      banReason: userColumns.has('ban_reason') ? text(row.ban_reason) : null,
      banExpires: userColumns.has('ban_expires') ? iso(row.ban_expires) : null,
      isAnonymous: userColumns.has('is_anonymous') ? row.is_anonymous === true : null,
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
  client: Client,
  table: string,
  columns: readonly string[],
  /**
   * Columns read only when the layout has them (issue #88: row
   * timestamps) — an absent optional column is simply not selected,
   * and the row carries no key for it.
   */
  optionalColumns: readonly string[] = []
): Promise<SourceRow[]> {
  if (!(await tableExists(client, table))) {
    throw new Error(`source table '${table}' is missing — run probeSourceLayout first`)
  }
  const existing = optionalColumns.length > 0 ? await columnsOf(client, table) : new Set<string>()
  const selected = [...columns, ...optionalColumns.filter((column) => existing.has(column))]
  const result = await client.query(`SELECT ${selected.join(', ')} FROM ${table} ORDER BY id`)
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
  client: Client,
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
