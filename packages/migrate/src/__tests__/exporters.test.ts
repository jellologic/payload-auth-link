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
import { exportToJsonl } from '../exporters.js'

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
    expect(result.totalRows).toBe(32)

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
})
