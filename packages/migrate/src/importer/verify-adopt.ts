import { isRecord } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { introspectDatabase } from '../doctor/database.js'
import type { VerifyIssue, VerifyResult } from './lifecycle.js'
import { columnsOf, openSource, type SourceClient } from './source.js'
import type { ResolvedSourceTables } from './types.js'

/**
 * `verify` for an ADOPT-mode app (issue #116). Adopt copies nothing —
 * Better Auth serves the payload-auth tables themselves — so there is
 * no source/target pair to compare. What CAN go wrong is checked
 * instead, against the live tables and the booted app:
 *
 * - the app serves every user row (Payload's count of the users
 *   collection equals the table's row count);
 * - every user resolves through EXACTLY ONE `better-auth` identity
 *   whose `providerUserId` is the document id (what `adopt-prelink`
 *   writes; until it runs, sign-ins depend on JIT linking);
 * - every account, member, invitation, and API key references an
 *   existing row; every credential account carries its hash.
 *
 * It also prints content checksums of the credential-bearing tables
 * (info, never failing): run `verify` right before the deploy and right
 * after the boot — before traffic writes them — and compare. Those
 * must match exactly.
 */

/** A checksum query per table: `count(*)` + an md5 over its key columns. */
const checksumColumns: readonly {
  readonly model: 'accounts' | 'users' | 'api_keys' | 'jwks'
  readonly columns: readonly string[]
}[] = [
  { model: 'accounts', columns: ['id', 'password', 'provider_id', 'account_id'] },
  { model: 'users', columns: ['id', 'email', 'email_verified'] },
  { model: 'api_keys', columns: ['id', 'key'] },
  { model: 'jwks', columns: ['id', 'public_key'] },
]

async function checksum(
  client: SourceClient,
  table: string,
  wanted: readonly string[]
): Promise<string> {
  const present = await columnsOf(client, table)
  const columns = wanted.filter((column) => present.has(column))
  if (!columns.includes('id')) {
    return `skipped: '${table}' has no id column`
  }
  const row = columns.map((column) => `coalesce(${column}::text, '')`).join(` || ':' || `)
  const result = await client.query(
    `SELECT count(*)::int AS n, coalesce(md5(string_agg(${row}, ',' ORDER BY id)), '') AS sum FROM ${table}`
  )
  const first = result.rows[0]
  const count = isRecord(first) && typeof first['n'] === 'number' ? first['n'] : 0
  const sum = isRecord(first) && typeof first['sum'] === 'string' ? first['sum'] : ''
  return `${count} row(s), md5 ${sum === '' ? '(empty)' : sum} over (${columns.join(', ')})`
}

/** The users collection an adopt-mode app serves Better Auth from. */
export function adoptUsersSlug(payload: Payload, preferred: string): string {
  if (payload.collections[preferred] !== undefined) {
    return preferred
  }
  const admin: unknown = (payload.config as { admin?: unknown }).admin
  const adminUser = isRecord(admin) ? admin['user'] : undefined
  if (typeof adminUser === 'string' && payload.collections[adminUser] !== undefined) {
    return adminUser
  }
  return 'users'
}

export async function verifyAdopt(options: {
  readonly payload: Payload
  readonly sourceConnectionString: string
  readonly sourceTables: ResolvedSourceTables
  readonly usersSlug: string
}): Promise<VerifyResult> {
  const { payload, sourceConnectionString, sourceTables, usersSlug } = options
  const issues: VerifyIssue[] = []
  const checks: { name: string; passed: boolean }[] = []
  const check = (name: string, passed: boolean, detail: string): void => {
    checks.push({ name, passed })
    if (!passed) {
      issues.push({ code: 'verify-mismatch', detail })
    }
  }
  const info = (name: string): void => {
    checks.push({ name, passed: true })
  }
  if (payload.collections[usersSlug] === undefined) {
    return {
      ok: false,
      issues: [
        {
          code: 'verify-adopt-no-users',
          detail: `the config declares no '${usersSlug}' collection to serve Better Auth's users from`,
        },
      ],
      checks,
    }
  }

  // References and counts, read off the live tables (the doctor's own
  // introspection: map-aware, fail-closed on a missing mapped table).
  const found = await introspectDatabase(sourceConnectionString, { sourceTables })
  for (const missing of found.missingTables ?? []) {
    issues.push({
      code: 'source-table-missing',
      detail: `model '${missing.model}' expects table '${missing.table}', which does not exist — pass --source-map with your layout's table names`,
    })
  }
  if (issues.length > 0) {
    return { ok: false, issues, checks }
  }

  const usersTable = sourceTables['users']
  const tableUsers =
    usersTable === null
      ? null
      : (found.tables.find((table) => table.name === usersTable)?.rows ?? 0)
  const served = (await payload.count({ collection: usersSlug, overrideAccess: true })).totalDocs
  if (tableUsers !== null) {
    check(
      'the app serves every user row',
      served === tableUsers,
      `table '${String(usersTable)}' holds ${tableUsers} user(s), and the '${usersSlug}' collection serves ${served}`
    )
  }

  // Identity resolution: one better-auth identity per user, keyed by the
  // document id (adopt mode's Better Auth user id).
  let unlinked = 0
  let conflicting = 0
  for (let page = 1; ; page += 1) {
    const batch = await payload.find({
      collection: usersSlug,
      depth: 0,
      limit: 200,
      page,
      sort: 'id',
      overrideAccess: true,
      select: { identities: true },
    })
    for (const doc of batch.docs as unknown as Record<string, unknown>[]) {
      const identities = Array.isArray(doc['identities'])
        ? (doc['identities'] as unknown[]).filter(isRecord)
        : []
      const own = identities.filter((row) => row['providerId'] === 'better-auth')
      if (own.length === 0) {
        unlinked += 1
      } else if (own.length !== 1 || String(own[0]?.['providerUserId']) !== String(doc['id'])) {
        conflicting += 1
      }
    }
    if (!batch.hasNextPage) {
      break
    }
  }
  check(
    'every user resolves through one better-auth identity (the document id)',
    unlinked === 0 && conflicting === 0,
    `${unlinked} user(s) carry no better-auth identity (run adopt-prelink --apply; until then their sign-in depends on JIT linking) and ${conflicting} carry one that does not resolve to their own document id (resolve those links by hand)`
  )

  check(
    'every account, member, invitation, and API key references an existing row',
    found.orphans.length === 0,
    `orphaned rows: ${found.orphans.map((orphan) => `${orphan.count} ${orphan.kind}`).join(', ')}`
  )
  for (const skipped of found.skippedChecks ?? []) {
    info(`reference check ${skipped}`)
  }

  const client = await openSource(sourceConnectionString)
  try {
    const accountsTable = sourceTables['accounts']
    if (accountsTable !== null) {
      const columns = await columnsOf(client, accountsTable)
      if (columns.has('provider_id') && columns.has('password')) {
        const result = await client.query(
          `SELECT count(*)::int AS n FROM ${accountsTable}
           WHERE provider_id = 'credential' AND (password IS NULL OR password = '')`
        )
        const first = result.rows[0]
        const broken = isRecord(first) && typeof first['n'] === 'number' ? first['n'] : 0
        check(
          'every credential account carries its hash',
          broken === 0,
          `${broken} credential account(s) in '${accountsTable}' without a password hash`
        )
      }
    }
    // Content checksums: compare across the deploy (info).
    for (const entry of checksumColumns) {
      const table = sourceTables[entry.model]
      if (table === null) {
        continue
      }
      info(`checksum ${table} (info): ${await checksum(client, table, entry.columns)}`)
    }
    const sessionsTable = sourceTables['sessions']
    if (sessionsTable !== null) {
      const result = await client.query(
        `SELECT count(*)::int AS n FROM ${sessionsTable} WHERE expires_at > now()`
      )
      const first = result.rows[0]
      const live = isRecord(first) && typeof first['n'] === 'number' ? first['n'] : 0
      info(
        `live sessions in ${sessionsTable} (info): ${live} — across the deploy this may only drop by sessions that expired in between`
      )
    }
  } finally {
    await client.end()
  }
  return { ok: issues.length === 0, issues, checks }
}
