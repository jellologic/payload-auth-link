/**
 * Issue #88 acceptance, against the real payload-auth dump, driven
 * through the CLI IN-PROCESS (`cliMain` with captured sinks — never a
 * spawned `bun <src>.ts`, which cannot resolve workspace imports on a
 * fresh clone). The CLI loads the target config module and boots its
 * OWN Payload instance, exactly as `--config` does in production, so
 * these tests prove:
 *
 * - every command's success path PRINTS (it used to print nothing) and
 *   TERMINATES — the booted Payload is destroyed and no connection to
 *   the database outlives the command;
 * - apply → apply → rollback restores the host users EXACTLY
 *   (`updated_at` included), never the imported state, and the
 *   manifest's totals never double;
 * - the manifest holds no email in the clear and is mode 0600;
 * - Better Auth admin-plugin bans carry (and a target that cannot hold
 *   them aborts the run); row `created_at` carries;
 * - `verify` tolerates sessions created after cutover.
 */
import { existsSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { cliMain } from '../cli.js'
import { introspectDatabase } from '../doctor/database.js'
import { pluginStateUnmappable } from '../importer/apply.js'
import type { SourceUser } from '../importer/source.js'
import type { ImportManifest } from '../importer/types.js'

const harnessPath = fileURLToPath(
  new URL('../../../../fixtures/payload-auth-app/test/harness.ts', import.meta.url)
)
type Harness = {
  dropDatabase: (database: string) => Promise<void>
  fixtureClient: (database: string) => Client
  loadFixtureDump: (prefix: string) => Promise<string>
  targetFromEnv: (database: string) => {
    host: string
    port: number
    user: string
    password: string
  }
}
const harness = (await import(harnessPath)) as Harness

const readSql = (name: string): string =>
  readFileSync(
    fileURLToPath(new URL(`../../../../fixtures/payload-auth-app/test/${name}`, import.meta.url)),
    'utf8'
  )
const adoptSchemaSql = readSql('adopt-schema.sql')
const targetSchemaSql = readSql('import-target-schema.sql')

const basicConfig = fileURLToPath(
  new URL('../__fixtures__/import-target/basic.config.ts', import.meta.url)
)
const adminConfig = fileURLToPath(
  new URL('../__fixtures__/import-target/admin.config.ts', import.meta.url)
)

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

type Run = { code: number; out: string; err: string }

async function run(argv: readonly string[]): Promise<Run> {
  const out: string[] = []
  const err: string[] = []
  const code = await cliMain(
    argv,
    { write: (chunk) => void out.push(chunk) },
    { write: (chunk) => void err.push(chunk) }
  )
  return { code, out: out.join(''), err: err.join('') }
}

describe.skipIf(!canReachPostgres)('migrate CLI lifecycle, in-process (#88)', () => {
  let database: string
  let url: string
  let manifestPath: string
  let client: Client

  const query = async <T>(sql: string, params: unknown[] = []): Promise<T[]> =>
    (await client.query(sql, params)).rows as T[]

  /**
   * Termination: once a command returns, nothing it opened may still
   * hold a connection to the database (the booted Payload's pool, the
   * source pg clients). Only this suite's own client remains.
   */
  async function expectNoLingeringConnections(): Promise<void> {
    let others = -1
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const rows = await query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_stat_activity
         WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [database]
      )
      others = rows[0]?.n ?? -1
      if (others === 0) {
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    expect(others, 'connections still open after the command returned').toBe(0)
  }

  /** The host users exactly as stored: every column, plus child rows. */
  async function hostSnapshot(): Promise<{
    users: unknown[]
    identities: unknown[]
    roles: unknown[]
  }> {
    return {
      users: await query('SELECT * FROM users ORDER BY id'),
      identities: await query('SELECT * FROM users_identities ORDER BY _parent_id, _order'),
      roles: await query(
        'SELECT parent_id, "order", value FROM users_role ORDER BY parent_id, "order"'
      ),
    }
  }

  const readManifestFile = (): ImportManifest =>
    JSON.parse(readFileSync(manifestPath, 'utf8')) as ImportManifest

  beforeAll(async () => {
    database = await harness.loadFixtureDump('pal_cli')
    const target = harness.targetFromEnv(database)
    url = `postgres://${target.user}:${target.password}@${target.host}:${target.port}/${database}`
    process.env.PAL_MIGRATE_TARGET_URL = url
    manifestPath = join(tmpdir(), `pal-cli-${Date.now()}.json`)
    client = harness.fixtureClient(database)
    await client.connect()
    await client.query(adoptSchemaSql)
    await client.query(targetSchemaSql)
    // The Better Auth admin + anonymous plugin columns: on the source
    // (payload-auth installed admin()) and on the target ba-* tables
    // (push stays off on the payload-auth layout).
    await client.query(`
      ALTER TABLE users ADD COLUMN banned boolean DEFAULT false;
      ALTER TABLE users ADD COLUMN ban_reason varchar;
      ALTER TABLE users ADD COLUMN ban_expires timestamptz;
      ALTER TABLE users ADD COLUMN is_anonymous boolean DEFAULT false;
      UPDATE users SET banned = true, ban_reason = 'chargeback',
        ban_expires = '2031-01-01T00:00:00Z' WHERE email = 'dave@example.com';
      ALTER TABLE ba_users ADD COLUMN IF NOT EXISTS banned boolean;
      ALTER TABLE ba_users ADD COLUMN IF NOT EXISTS ban_reason varchar;
      ALTER TABLE ba_users ADD COLUMN IF NOT EXISTS ban_expires timestamptz;
      ALTER TABLE ba_users ADD COLUMN IF NOT EXISTS role varchar;
      ALTER TABLE ba_users ADD COLUMN IF NOT EXISTS is_anonymous boolean;
      ALTER TABLE ba_sessions ADD COLUMN IF NOT EXISTS impersonated_by varchar;
    `)
  }, 240_000)

  afterAll(async () => {
    await client.end()
    rmSync(manifestPath, { force: true })
    await harness.dropDatabase(database)
  })

  test('a target that cannot hold bans aborts --apply with nothing written', async () => {
    const result = await run([
      'from-payload-auth',
      '--config',
      basicConfig,
      '--database-url',
      url,
      '--apply',
      '--manifest',
      manifestPath,
    ])
    expect(result.code).toBe(1)
    expect(result.out).toContain("declares no 'banned' field")
    expect(result.err).toContain('ABORT')
    expect((await query<{ n: number }>('SELECT count(*)::int AS n FROM ba_users'))[0]?.n).toBe(0)
    expect(existsSync(manifestPath)).toBe(false)
    await expectNoLingeringConnections()
  })

  test('the doctor flags the bans, and blocks on a target that cannot hold them', async () => {
    const found = await introspectDatabase(url)
    expect(found.bannedUsers).toBe(1)
    expect(found.anonymousUsers).toBe(0)
    const result = await run(['doctor', '--config', basicConfig, '--database-url', url, '--json'])
    const report = JSON.parse(result.out) as {
      blockers: { code: string }[]
      warnings: { code: string }[]
    }
    const blockers = report.blockers.map((issue) => issue.code)
    expect(blockers).toContain('target-cannot-hold-bans')
    // The plugin's own injected fields are not collisions on the target.
    expect(blockers).not.toContain('injected-field-collision')
    await expectNoLingeringConnections()
  })

  test('from-payload-auth dry run prints the plan and terminates', async () => {
    const result = await run([
      'from-payload-auth',
      '--config',
      adminConfig,
      '--database-url',
      url,
      '--manifest',
      manifestPath,
    ])
    expect(result.code, result.err).toBe(0)
    expect(result.out).toMatch(/user\s+4 row\(s\) -> ba-users/)
    expect(result.out).toContain('dry run: nothing was written')
    expect(existsSync(manifestPath)).toBe(false)
    await expectNoLingeringConnections()
  })

  let before: Awaited<ReturnType<typeof hostSnapshot>>

  test('--apply prints, terminates, carries bans and timestamps, and seals the manifest', async () => {
    before = await hostSnapshot()
    const result = await run([
      'from-payload-auth',
      '--config',
      adminConfig,
      '--database-url',
      url,
      '--apply',
      '--manifest',
      manifestPath,
    ])
    expect(result.code, result.err).toBe(0)
    expect(result.out).toContain('applied: manifest at')
    await expectNoLingeringConnections()

    // A banned user stays banned; the admin-plugin role string carries.
    const dave = await query<{ banned: boolean; ban_reason: string; role: string }>(
      "SELECT banned, ban_reason, role FROM ba_users WHERE email = 'dave@example.com'"
    )
    expect(dave[0]?.banned).toBe(true)
    expect(dave[0]?.ban_reason).toBe('chargeback')
    const alice = await query<{ banned: boolean }>(
      "SELECT banned FROM ba_users WHERE email = 'alice@example.com'"
    )
    expect(alice[0]?.banned).toBe(false)

    // Row created_at carries for every model whose source has it.
    for (const [source, target, prefix] of [
      ['accounts', 'ba_accounts', 'acct-'],
      ['organizations', 'ba_organization', 'org-'],
      ['members', 'ba_member', 'member-'],
      ['api_keys', 'ba_apikey', 'key-'],
      ['invitations', 'ba_invitation', 'inv-'],
    ] as const) {
      const mismatched = await query<{ id: number }>(
        `SELECT s.id FROM ${source} s
         JOIN ${target} t ON t.ba_id = '${prefix}' || s.id::text
         WHERE t.created_at IS DISTINCT FROM s.created_at`
      )
      expect(mismatched, `${target}.created_at`).toEqual([])
      const joined = await query<{ n: number }>(
        `SELECT count(*)::int AS n FROM ${source} s JOIN ${target} t ON t.ba_id = '${prefix}' || s.id::text`
      )
      expect(joined[0]?.n, target).toBeGreaterThan(0)
    }

    // The manifest: owner-only, no email in the clear.
    expect(statSync(manifestPath).mode & 0o777).toBe(0o600)
    const raw = readFileSync(manifestPath, 'utf8')
    expect(raw).not.toMatch(/@example\.com/)
    const manifest = readManifestFile()
    expect(manifest.version).toBe(2)
    expect(manifest.totals['user']).toBe(4)
    expect(manifest.fieldWrites.every((write) => write.sealedBefore !== undefined)).toBe(true)
  })

  test('a second --apply neither doubles totals nor re-captures prior values', async () => {
    const first = readManifestFile()
    const result = await run([
      'from-payload-auth',
      '--config',
      adminConfig,
      '--database-url',
      url,
      '--apply',
      '--manifest',
      manifestPath,
    ])
    expect(result.code, result.err).toBe(0)
    expect(result.out).toContain('already present')
    await expectNoLingeringConnections()
    const second = readManifestFile()
    expect(second.totals).toEqual(first.totals)
    expect(second.fieldWrites).toEqual(first.fieldWrites)
    expect(second.created).toEqual(first.created)
  })

  test('verify prints its checks, passes, and tolerates sessions created after cutover', async () => {
    // A sign-in after go-live: a live ba-sessions row the import never made.
    await client.query(
      `INSERT INTO ba_sessions (ba_id, user_id, token, expires_at)
       VALUES ('live-after-cutover', '1', 'live-token-after-cutover', now() + interval '1 day')`
    )
    try {
      const result = await run(['verify', '--config', adminConfig, '--database-url', url])
      expect(result.code, result.out).toBe(0)
      expect(result.out).toContain('banned source users stay banned')
      expect(result.out).toContain('1 created since the import')
      expect(result.out).toContain('verify: ok')
      await expectNoLingeringConnections()
    } finally {
      await client.query("DELETE FROM ba_sessions WHERE ba_id = 'live-after-cutover'")
    }
  })

  test('rollback after two applies restores the host users exactly and resets the manifest', async () => {
    const result = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
    expect(result.code, result.err).toBe(0)
    expect(result.out).toMatch(/rollback: \d+ row\(s\) deleted, \d+ field value\(s\) restored/)
    await expectNoLingeringConnections()

    for (const table of [
      'ba_users',
      'ba_accounts',
      'ba_sessions',
      'ba_verifications',
      'ba_apikey',
      'ba_jwks',
      'ba_organization',
      'ba_member',
      'ba_invitation',
    ]) {
      const counted = await query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`)
      expect(counted[0]?.n, table).toBe(0)
    }
    const after = await hostSnapshot()
    // Every users column — updated_at included — is the pre-import value.
    expect(after.users).toEqual(before.users)
    expect(after.identities).toEqual(before.identities)
    // hasMany role rows: values and order restored (their row ids are
    // re-created by the Local API write — documented).
    expect(after.roles).toEqual(before.roles)

    const reset = readManifestFile()
    expect(reset.created).toEqual([])
    expect(reset.fieldWrites).toEqual([])
    expect(reset.rolledBackAt).toBeDefined()
  })

  test('re-apply after rollback starts fresh; finalize prints and terminates', async () => {
    const applied = await run([
      'from-payload-auth',
      '--config',
      adminConfig,
      '--database-url',
      url,
      '--apply',
      '--manifest',
      manifestPath,
    ])
    expect(applied.code, applied.err).toBe(0)
    const manifest = readManifestFile()
    expect(manifest.totals['user']).toBe(4)
    expect(manifest.created.filter((row) => row.collection === 'ba-users')).toHaveLength(4)
    await expectNoLingeringConnections()

    const finalized = await run(['finalize', '--manifest', manifestPath])
    expect(finalized.code).toBe(0)
    expect(finalized.out).toContain('finalized: the manifest at')
    expect(readManifestFile().finalized).toBe(true)
  })
})

describe('plugin user state the target cannot hold (#88)', () => {
  const user = (overrides: Partial<SourceUser>): SourceUser => ({
    id: '1',
    email: 'u@example.com',
    name: null,
    emailVerified: true,
    image: null,
    createdAt: new Date(0),
    updatedAt: new Date(0),
    roles: [],
    accounts: [],
    banned: null,
    banReason: null,
    banExpires: null,
    isAnonymous: null,
    ...overrides,
  })

  test('banned and anonymous users are unmappable without the target fields', () => {
    const users = [
      user({ id: '1', banned: true }),
      user({ id: '2', isAnonymous: true }),
      user({ id: '3', banned: false, isAnonymous: false }),
    ]
    const blocked = pluginStateUnmappable(users, new Set(['email']), 'ba-users')
    expect(blocked.map((row) => row.key)).toEqual(['1', '2'])
    expect(pluginStateUnmappable(users, new Set(['banned', 'isAnonymous']), 'ba-users')).toEqual([])
  })
})
