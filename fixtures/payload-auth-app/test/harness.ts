/**
 * Test harness for the payload-auth fixture database (issue #59).
 *
 * Loads the committed dump into a fresh per-run database and hands out
 * `pg` clients, so every migration feature (#49 adopt, #50 importer,
 * #51 coexistence, #52 doctor) tests against the same real rows.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { Client } from 'pg'

const fixtureDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
export const dumpPath = path.join(fixtureDir, '..', 'dumps', 'payload-auth-1.9.4.sql')

export type PostgresTarget = {
  readonly host: string
  readonly port: number
  readonly user: string
  readonly password: string
  readonly database: string
}

export function targetFromEnv(database: string): PostgresTarget {
  const url =
    process.env.FIXTURE_DATABASE_URL ?? 'postgres://postgres:payload@localhost:5433/pal_fixture'
  const parsed = new URL(url)
  return {
    host: parsed.hostname,
    port: Number(parsed.port || '5432'),
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database,
  }
}

function adminClient(target: PostgresTarget): Client {
  return new Client({
    host: target.host,
    port: target.port,
    user: target.user,
    password: target.password,
    database: 'postgres',
  })
}

export function fixtureClient(database: string): Client {
  const target = targetFromEnv(database)
  return new Client({
    host: target.host,
    port: target.port,
    user: target.user,
    password: target.password,
    database,
  })
}

/**
 * Create a fresh database and load the committed dump. `--clean
 * --if-exists` statements no-op on an empty database, so the same file
 * loads anywhere. Returns the database name.
 */
export async function loadFixtureDump(prefix: string): Promise<string> {
  const database = `${prefix}_${Date.now()}_${Math.floor(Math.random() * 1e6)}`
    .replace(/[^a-z0-9_]/gi, '_')
    .toLowerCase()
  const admin = adminClient(targetFromEnv(database))
  await admin.connect()
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${quoteIdent(database)}`)
    await admin.query(`CREATE DATABASE ${quoteIdent(database)}`)
  } finally {
    await admin.end()
  }
  // pg_dump's psql meta-commands (\restrict/\unrestrict) are a shell
  // guard, not SQL; the `pg` driver executes plain statements only.
  const sql = readFileSync(dumpPath, 'utf8')
    .split('\n')
    .filter((line) => !line.startsWith('\\'))
    .join('\n')
  const client = fixtureClient(database)
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end()
  }
  return database
}

/**
 * Best-effort cleanup: WITH (FORCE) terminates live backends, and the
 * killed connections surface as unhandled pg errors that fail the run
 * even when every test passed. A failed drop (live connections) is
 * ignored — the suite stays green and the leftover database is garbage
 * collected by the next scratch purge.
 */
export async function dropDatabase(database: string): Promise<void> {
  const admin = adminClient(targetFromEnv(database))
  await admin.connect()
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${quoteIdent(database)}`)
  } catch {
    // Live connections; leave the database for the next purge.
  } finally {
    await admin.end()
  }
}

function quoteIdent(identifier: string): string {
  if (!/^[a-z0-9_]+$/.test(identifier)) {
    throw new Error(`refusing unsafe database identifier: ${identifier}`)
  }
  return `"${identifier}"`
}

/** The committed dump's own sanity contract, shared by every consumer. */
export const expectedCounts: Readonly<Record<string, number>> = {
  users: 4,
  accounts: 6,
  sessions: 6,
  verifications: 1,
  api_keys: 2,
  organizations: 2,
  members: 3,
  invitations: 2,
  jwks: 1,
}
