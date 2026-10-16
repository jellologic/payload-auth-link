import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'

// Runtime-computed specifier: the typecheck project never reaches into
// fixtures/ (the fixture app owns its dependency tree).
const harnessPath = fileURLToPath(
  new URL('../../../../fixtures/payload-auth-app/test/harness.ts', import.meta.url)
)
type Harness = {
  dropDatabase: (database: string) => Promise<void>
  fixtureClient: (database: string) => import('pg').Client
  loadFixtureDump: (prefix: string) => Promise<string>
  targetFromEnv: (database: string) => {
    host: string
    port: number
    user: string
    password: string
  }
}
const harness = (await import(harnessPath)) as Harness
import { cliMain } from '../cli.js'
import { exportToJsonl, parseExportTables } from '../exporters.js'

describe('--tables flag parsing (#68)', () => {
  test('accepts a JSON array or a comma-separated list', () => {
    expect(parseExportTables('users, accounts')).toEqual(['users', 'accounts'])
    expect(parseExportTables('["users","api_keys"]')).toEqual(['users', 'api_keys'])
    expect(parseExportTables(' users_role ')).toEqual(['users_role'])
  })
  test('rejects anything that is not a list of table names', () => {
    expect(() => parseExportTables('')).toThrow(/--tables/)
    expect(() => parseExportTables('{"users":1}')).toThrow(/--tables/)
    expect(() => parseExportTables('[1,2]')).toThrow(/table names/)
  })
})

/**
 * Off-ramp JSONL export against the real fixture (issue #58): every
 * auth table exports losslessly — counts match, plugin-injected
 * columns (identities, linkable, suspension, roles child rows) are in
 * the JSON, and a re-parse of the JSONL reproduces the exact rows.
 * Postgres-gated: runs in the migration-fixture CI job.
 */
const canReachPostgres = await (async () => {
  try {
    const probe = harness.fixtureClient('postgres')
    await probe.connect()
    await probe.end()
    return true
  } catch {
    return false
  }
})()

describe.skipIf(!canReachPostgres)('export --to jsonl (issue #58)', () => {
  let database: string
  beforeAll(async () => {
    database = await harness.loadFixtureDump('pal_export')
  }, 120_000)
  afterAll(async () => {
    await harness.dropDatabase(database)
  })

  test('exports every auth table with exact counts and full columns', async () => {
    const { password, port, user } = harness.targetFromEnv(database)
    const result = await exportToJsonl({
      connectionString: `postgres://${user}:${password}@localhost:${port}/${database}`,
      format: 'jsonl',
    })
    const byName = new Map(result.tables.map((t) => [t.name, t.rows]))
    expect(byName.get('users')).toBe(4)
    expect(byName.get('accounts')).toBe(6)
    expect(byName.get('sessions')).toBe(6)
    expect(byName.get('api_keys')).toBe(2)
    expect(byName.get('organizations')).toBe(2)
    expect(byName.get('members')).toBe(3)
    expect(byName.get('invitations')).toBe(2)
    expect(byName.get('jwks')).toBe(1)
    // Every auth table (#110): org child tables and payload-auth's other
    // Better Auth plugin tables export too, when present.
    expect(byName.get('organizations_tags')).toBe(2)
    expect(byName.get('admin_invitations')).toBe(0)
    expect(byName.has('payload_kv')).toBe(false)
    expect(result.missing).toEqual([])
    expect(result.totalRows).toBe(34)

    // Lossless: the JSONL re-parses to the exact rows, including
    // plugin-injected and role child rows.
    const lines = result.jsonl.trim().split('\n')
    expect(lines.length).toBe(result.totalRows)
    const parsed = lines.map(
      (line) => JSON.parse(line) as { table: string; row: Record<string, unknown> }
    )
    const roleRows = parsed.filter((entry) => entry.table === 'users_role')
    expect(roleRows.map((entry) => entry.row.value)).toContain('frontPlugin')
    const users = parsed.filter((entry) => entry.table === 'users')
    const alice = users.find((entry) => entry.row.email === 'alice@example.com')
    const carol = users.find((entry) => entry.row.email === 'carol@example.com')
    // Every column exports, host-added and payload-auth alike.
    expect(alice?.row.email_verified).toBe(true)
    expect(carol?.row.department).toBe('ops')
    // Credential hashes export verbatim.
    const accounts = parsed.filter((entry) => entry.table === 'accounts')
    const credential = accounts.find((entry) => entry.row.provider_id === 'credential')
    expect(String(credential?.row.password)).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/)
  })

  test('a requested table that does not exist lands in missing, never silently omitted (#68)', async () => {
    const { password, port, user } = harness.targetFromEnv(database)
    const result = await exportToJsonl({
      connectionString: `postgres://${user}:${password}@localhost:${port}/${database}`,
      format: 'jsonl',
      tables: ['users', 'not_a_real_table'],
    })
    expect(result.missing).toEqual(['not_a_real_table'])
    expect(result.tables.map((table) => table.name)).toEqual(['users'])
  })

  test('--source-map: a custom-slug layout exports every table; a missing mapped table exits 1 (#110)', async () => {
    const { password, port, user } = harness.targetFromEnv(database)
    const url = `postgres://${user}:${password}@localhost:${port}/${database}`
    const client = harness.fixtureClient(database)
    await client.connect()
    await client.query(
      'ALTER TABLE accounts RENAME TO user_accounts; ALTER TABLE sessions RENAME TO user_sessions'
    )
    try {
      const run = async (argv: readonly string[]) => {
        const out: string[] = []
        const err: string[] = []
        const code = await cliMain(
          argv,
          { write: (chunk) => void out.push(chunk) },
          { write: (chunk) => void err.push(chunk) }
        )
        return { code, out: out.join(''), err: err.join('') }
      }
      // Without the map, the renamed tables are mapped-but-missing.
      const unmapped = await run(['export', '--database-url', url])
      expect(unmapped.code).toBe(1)
      expect(unmapped.err).toContain("table 'accounts' does not exist")
      expect(unmapped.err).toContain("table 'sessions' does not exist")
      // With it, they export — and stdout is pure JSONL.
      const mapped = await run([
        'export',
        '--database-url',
        url,
        '--source-map',
        '{"accounts":"user_accounts","sessions":"user_sessions"}',
      ])
      expect(mapped.code, mapped.err).toBe(0)
      const tables = mapped.out
        .trim()
        .split('\n')
        .map((line) => (JSON.parse(line) as { table: string }).table)
      expect(tables.filter((table) => table === 'user_accounts')).toHaveLength(6)
      expect(tables.filter((table) => table === 'user_sessions')).toHaveLength(6)
      // A model mapped to a table that does not exist is an error, too.
      const typo = await run([
        'export',
        '--database-url',
        url,
        '--source-map',
        '{"accounts":"user_acounts","sessions":"user_sessions"}',
      ])
      expect(typo.code).toBe(1)
      expect(typo.err).toContain("table 'user_acounts' does not exist")
    } finally {
      await client.query(
        'ALTER TABLE user_accounts RENAME TO accounts; ALTER TABLE user_sessions RENAME TO sessions'
      )
      await client.end()
    }
  })
})
