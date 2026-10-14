/**
 * The fixture contract (issue #59): the committed dump is a real
 * payload-auth 1.9.4 database, and it contains everything every
 * migration feature is tested against. Every later item — #49 adopt,
 * #50 importer, #51 coexistence, #52 doctor — boots from these rows.
 *
 * Postgres-only by design (the dump IS Postgres); runs in the
 * `migration-fixture` CI job and locally against the `pal-pg` docker
 * container on :5433.
 */
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import {
  dropDatabase,
  expectedCounts,
  fixtureClient,
  loadFixtureDump,
  targetFromEnv,
  type PostgresTarget,
} from './harness.js'

let database: string
let client: Awaited<ReturnType<typeof fixtureClient>>
let target: PostgresTarget

beforeAll(async () => {
  database = await loadFixtureDump('pal_contract')
  target = targetFromEnv(database)
  client = fixtureClient(database)
  await client.connect()
}, 60_000)

afterAll(async () => {
  await client?.end()
  await dropDatabase(database)
})

async function scalar(sql: string): Promise<unknown> {
  const result = await client.query(sql)
  const first: Record<string, unknown> | undefined = result.rows[0]
  return first === undefined ? undefined : Object.values(first)[0]
}

async function countRows(table: string): Promise<number> {
  const result = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
  return result.rows[0]?.n ?? -1
}

describe('fixture contract: a real payload-auth 1.9.4 database', () => {
  test('every auth table exists with the expected row count', async () => {
    for (const [table, expected] of Object.entries(expectedCounts)) {
      expect(await countRows(table), table).toBe(expected)
    }
  })

  test('email+password users: verified and unverified, with scrypt hashes', async () => {
    // Unverified users exist — they are the doctor's "won't JIT-link"
    // rows and the importer must NOT grant them `linkable` (#50).
    const verified = await client.query('SELECT email, email_verified FROM users ORDER BY id')
    expect(verified.rows.map((row) => row.email)).toEqual([
      'alice@example.com',
      'bob@example.com',
      'carol@example.com',
      'dave@example.com',
    ])
    expect(verified.rows.filter((row) => row.email_verified)).toEqual([
      expect.objectContaining({ email: 'alice@example.com' }),
      expect.objectContaining({ email: 'carol@example.com' }),
    ])
    // Credential accounts carry Better Auth's own hash, copied
    // verbatim by the importer (#50).
    const hashes = await client.query(
      "SELECT user_id, password FROM accounts WHERE provider_id = 'credential'"
    )
    expect(hashes.rows).toHaveLength(4)
    // Better Auth's scrypt encoding: 32-hex salt, colon, 128-hex key —
    // copied verbatim, verified by an old-password sign-in later (#50).
    for (const row of hashes.rows) {
      expect(String(row.password)).toMatch(/^[0-9a-f]{32}:[0-9a-f]{128}$/)
    }
  })

  test('OAuth accounts exist with tokens', async () => {
    const oauth = await client.query(
      "SELECT provider_id, account_id, access_token FROM accounts WHERE provider_id <> 'credential' ORDER BY id"
    )
    expect(oauth.rows.map((row) => row.provider_id)).toEqual(['google', 'generic-oauth'])
    expect(oauth.rows[0]?.access_token).toBe('at_google_fixture')
  })

  test('the camelCase role value survives in the hasMany role field', async () => {
    // Payload stores a hasMany select as rows in `users_role`; the
    // stored value must stay exactly `frontPlugin` (#56).
    const roles = await client.query('SELECT parent_id, value FROM users_role ORDER BY id')
    const values = roles.rows.map((row) => row.value)
    expect(values).toContain('frontPlugin')
    expect(values).toContain('admin')
    const bob = await client.query("SELECT id FROM users WHERE email = 'bob@example.com'")
    const bobRoles = roles.rows
      .filter((row) => row.parent_id === bob.rows[0]?.id)
      .map((row) => row.value)
    expect(bobRoles).toEqual(['frontPlugin', 'user'])
  })

  test('magic-link verification row exists and is unexpired', async () => {
    const rows = await client.query(
      'SELECT identifier, expires_at FROM verifications WHERE expires_at > now()'
    )
    expect(rows.rows.length).toBeGreaterThanOrEqual(1)
    expect(rows.rows[0]?.identifier).toBeTruthy()
  })

  test('active sessions exist', async () => {
    const rows = await client.query(
      'SELECT token, user_id, expires_at FROM sessions WHERE expires_at > now()'
    )
    expect(rows.rows.length).toBe(6)
    expect(new Set(rows.rows.map((row) => row.user_id)).size).toBe(4)
  })

  test('API keys carry metadata and rate-limit state', async () => {
    const rows = await client.query(
      'SELECT name, start, metadata, rate_limit_enabled, remaining FROM api_keys ORDER BY id'
    )
    expect(rows.rows[0]).toMatchObject({
      name: 'ci-key',
      rate_limit_enabled: true,
    })
    expect(String(rows.rows[0]?.remaining)).toBe('97')
    expect(JSON.parse(rows.rows[0]?.metadata ?? '{}')).toEqual({
      env: 'ci',
      scopes: ['pages.read', 'pages.write'],
    })
    expect(JSON.parse(rows.rows[1]?.metadata ?? '{}')).toEqual({
      env: 'prod',
      scopes: ['pages.read'],
    })
  })

  test('organizations keep host-added fields: group, array, relationship', async () => {
    const acme = await client.query("SELECT * FROM organizations WHERE slug = 'acme'")
    expect(acme.rows).toHaveLength(1)
    const org = acme.rows[0]
    expect(org.billing_plan).toBe('pro')
    // Payload's number fields land as Postgres numerics, which `pg`
    // hands back as strings.
    expect(String(org.billing_seats)).toBe('12')
    expect(Number(org.owner_id)).toBe(1)
    // Payload arrays store children ordered by `_order`, keyed by
    // `_parent_id`, with generated text ids.
    const tags = await client.query(
      'SELECT label FROM organizations_tags WHERE _parent_id = $1 ORDER BY _order',
      [org.id]
    )
    expect(tags.rows.map((row) => row.label)).toEqual(['launch', 'beta'])
  })

  test('members and invitations reference real orgs and users', async () => {
    const broken = await client.query(
      `SELECT m.id FROM members m
       LEFT JOIN organizations o ON o.id = m.organization_id
       LEFT JOIN users u ON u.id = m.user_id
       WHERE o.id IS NULL OR u.id IS NULL`
    )
    expect(broken.rows).toEqual([])
    const invitations = await client.query(
      'SELECT email, status, role FROM invitations ORDER BY id'
    )
    // Both payload-auth-produced invitations are pending; carol's is
    // the never-accepted row the coexistence tests reason about.
    expect(invitations.rows.map((row) => [row.email, row.status])).toEqual([
      ['bob@example.com', 'pending'],
      ['carol@example.com', 'pending'],
    ])
  })

  test('jwks carries the signing key material', async () => {
    const rows = await client.query('SELECT public_key, private_key, expires_at FROM jwks')
    expect(rows.rows).toHaveLength(1)
    // BA 1.6's jwt plugin stores the signing key as JSON key material
    // (no `alg` column yet — that arrives with the 1.7 oauth-provider
    // split the journey logs in #60).
    expect(() => JSON.parse(String(rows.rows[0]?.private_key))).not.toThrow()
  })

  test('a local Postgres boot of the same shape is reachable', async () => {
    // The harness target must be the shape every later test (#49/#50)
    // reuses — prove the credentials resolve a working connection.
    expect(target.port).toBeGreaterThan(0)
    expect(await scalar('SELECT current_database()')).toBe(database)
  })
})
