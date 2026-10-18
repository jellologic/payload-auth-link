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
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { cliMain } from '../cli.js'
import { introspectDatabase } from '../doctor/database.js'
import { pluginStateUnmappable } from '../importer/apply.js'
import type { SourceUser } from '../importer/source.js'
import { signManifest } from '../importer/manifest-mac.js'
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
/** The same app (same secret) against a second, rehearsal database. */
const rehearsalConfig = fileURLToPath(
  new URL('../__fixtures__/import-target/rehearsal.config.ts', import.meta.url)
)
/** `payload.secret` of the fixture app: Payload derives it from the config secret. */
const appSecret = createHash('sha256')
  .update('cli-lifecycle-secret-cli-lifecycle!')
  .digest('hex')
  .slice(0, 32)

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
    await prepareTarget(client)
  }, 240_000)

  /**
   * The additive target schema, plus the Better Auth admin + anonymous
   * plugin columns: on the source (payload-auth installed admin()) and
   * on the target ba-* tables (push stays off on the payload-auth
   * layout).
   */
  async function prepareTarget(on: Client): Promise<void> {
    await on.query(adoptSchemaSql)
    await on.query(targetSchemaSql)
    await on.query(`
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
  }

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
    expect(manifest.version).toBe(4)
    expect(manifest.mac).toMatch(/^v2\./)
    // Bound to THIS database and run (GHSA-crrr-3cg7-f6jw).
    const ids = await query<{ data: { id: string } }>(
      "SELECT data FROM payload_kv WHERE key = 'payload-auth-link/migrate/database-id'"
    )
    expect(manifest.databaseId).toBe(ids[0]?.data.id)
    const runs = await query<{ data: { state: string } }>(
      'SELECT data FROM payload_kv WHERE key = $1',
      [`payload-auth-link/migrate/runs/${String(manifest.runId)}`]
    )
    expect(runs[0]?.data.state).toBe('open')
    expect(manifest.totals['user']).toBe(4)

    // Timestamps (issue #113): ba_users.updated_at carries the SOURCE
    // value, and the first apply bumps the host users' updated_at
    // (rollback restores it — asserted below).
    const beforeById = new Map(
      (before.users as { id: number; updated_at: Date }[]).map((row) => [row.id, row.updated_at])
    )
    const baStamps = await query<{ ba_id: string; updated_at: Date }>(
      'SELECT ba_id, updated_at FROM ba_users'
    )
    for (const row of baStamps) {
      expect(row.updated_at, `ba_users ${row.ba_id}`).toEqual(beforeById.get(Number(row.ba_id)))
    }
    const hostStamps = await query<{ id: number; updated_at: Date }>(
      'SELECT id, updated_at FROM users ORDER BY id'
    )
    expect(
      hostStamps.some((row) => row.updated_at.getTime() !== beforeById.get(row.id)?.getTime())
    ).toBe(true)
    expect(manifest.fieldWrites.every((write) => write.sealedBefore !== undefined)).toBe(true)
  })

  test('a second --apply neither doubles totals nor re-captures prior values', async () => {
    const first = readManifestFile()
    // Every host row as stored, surrogate ids included (#110: a second
    // pass used to bump updated_at and linked_at, and re-create the
    // users_role rows with new ids).
    const exact = async (): Promise<unknown[]> => [
      await query('SELECT * FROM users ORDER BY id'),
      await query('SELECT * FROM users_identities ORDER BY _parent_id, _order'),
      await query('SELECT * FROM users_role ORDER BY parent_id, "order"'),
    ]
    const hostBefore = await exact()
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
    // A true no-op on the host: byte-identical rows.
    expect(await exact()).toEqual(hostBefore)
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

  // --- GHSA-crrr-3cg7-f6jw: an edited manifest must not alter the database ---

  test('GHSA-crrr case 1: an edited UNSIGNED manifest is never resumed or re-signed, and cannot delete a live user', async () => {
    const signed = readFileSync(manifestPath, 'utf8')
    const manifest = readManifestFile()
    // A sign-up after cutover: a LIVE ba-users row with Better Auth's own id.
    const live = await query<{ id: number }>(
      `INSERT INTO ba_users (ba_id, email, name, email_verified)
       VALUES ('live-ba-user-0001', 'live@example.com', 'Live', true) RETURNING id`
    )
    const liveId = live[0]?.id
    const roleBefore = await query(
      'SELECT parent_id, value FROM users_role ORDER BY parent_id, "order"'
    )
    const baBefore = await query('SELECT count(*)::int AS n FROM ba_users')
    // The advisory's edit: an unsigned v1 manifest that lists the live
    // row as created and sets users#3's role back to ["admin"] in plaintext.
    const edited = {
      version: 1,
      createdAt: manifest.createdAt,
      sourceDatabase: manifest.sourceDatabase,
      options: manifest.options,
      created: [
        ...manifest.created,
        { collection: 'ba-users', id: liveId, sourceKey: 'user:live-ba-user-0001' },
      ],
      fieldWrites: [{ collection: 'users', id: 3, field: 'role', before: '["admin"]' }],
      finalized: false,
      sourceCounts: manifest.sourceCounts,
      totals: manifest.totals,
    }
    const editedText = JSON.stringify(edited)
    try {
      writeFileSync(manifestPath, editedText)
      // 0.7.0 accepted this, re-signed it as v3 and exited 0.
      const resumed = await run([
        'from-payload-auth',
        '--config',
        adminConfig,
        '--database-url',
        url,
        '--apply',
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
        '--allow-unbound-manifest',
      ])
      expect(resumed.code).toBe(1)
      expect(resumed.err).toContain('never resumed or re-signed')
      expect(readFileSync(manifestPath, 'utf8')).toBe(editedText)
      // Rollback: deletes need their own flag, plaintext values another.
      const noDeletes = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
      ])
      expect(noDeletes.code).toBe(1)
      expect(noDeletes.err).toContain('--allow-unsigned-deletes')
      const noPlaintext = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
        '--allow-unsigned-deletes',
      ])
      expect(noPlaintext.code).toBe(1)
      expect(noPlaintext.err).toContain('--allow-plaintext-restore')
      // Every flag: the live row is still not provably an imported user.
      const everything = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
        '--allow-unsigned-deletes',
        '--allow-plaintext-restore',
      ])
      expect(everything.code).toBe(1)
      expect(everything.err).toContain('no host document with that id')
      expect(await query('SELECT count(*)::int AS n FROM ba_users')).toEqual(baBefore)
      expect(await query('SELECT id FROM ba_users WHERE id = $1', [liveId])).toHaveLength(1)
      expect(
        await query('SELECT parent_id, value FROM users_role ORDER BY parent_id, "order"')
      ).toEqual(roleBefore)
      await expectNoLingeringConnections()
    } finally {
      writeFileSync(manifestPath, signed, { mode: 0o600 })
      await client.query('DELETE FROM ba_users WHERE id = $1', [liveId])
    }
  })

  test('GHSA-crrr case 3: a signed manifest from ANOTHER database (same secret) changes nothing there', async () => {
    const db1Manifest = readFileSync(manifestPath, 'utf8')
    // A rehearsal database: same app, same PAYLOAD_SECRET, its own run.
    const other = await harness.loadFixtureDump('pal_cli_db2')
    const target = harness.targetFromEnv(other)
    const otherUrl = `postgres://${target.user}:${target.password}@${target.host}:${target.port}/${other}`
    const otherClient = harness.fixtureClient(other)
    await otherClient.connect()
    const otherManifest = join(tmpdir(), `pal-cli-db2-${Date.now()}.json`)
    const replay = join(tmpdir(), `pal-cli-replay-${Date.now()}.json`)
    try {
      await prepareTarget(otherClient)
      process.env.PAL_MIGRATE_REHEARSAL_URL = otherUrl
      const applied = await run([
        'from-payload-auth',
        '--config',
        rehearsalConfig,
        '--database-url',
        otherUrl,
        '--apply',
        '--manifest',
        otherManifest,
      ])
      expect(applied.code, applied.err).toBe(0)
      const snapshot = async (): Promise<unknown[]> => [
        (await otherClient.query('SELECT * FROM users ORDER BY id')).rows,
        (await otherClient.query('SELECT count(*)::int AS n FROM ba_users')).rows,
        (await otherClient.query('SELECT * FROM users_identities ORDER BY _parent_id, _order'))
          .rows,
      ]
      const before2 = await snapshot()
      writeFileSync(replay, db1Manifest, { mode: 0o600 })
      for (const argv of [
        ['rollback', '--config', rehearsalConfig, '--manifest', replay],
        [
          'from-payload-auth',
          '--config',
          rehearsalConfig,
          '--database-url',
          otherUrl,
          '--apply',
          '--manifest',
          replay,
        ],
        ['finalize', '--config', rehearsalConfig, '--manifest', replay],
      ]) {
        const refused = await run(argv)
        expect(refused.code, argv[0]).toBe(1)
        expect(refused.err, argv[0]).toContain('different database')
      }
      // Finalized, the rehearsal database refuses it for that reason too.
      const finalized = await run([
        'finalize',
        '--config',
        rehearsalConfig,
        '--manifest',
        otherManifest,
      ])
      expect(finalized.code, finalized.err).toBe(0)
      const afterFinalize = await run([
        'rollback',
        '--config',
        rehearsalConfig,
        '--manifest',
        replay,
      ])
      expect(afterFinalize.code).toBe(1)
      expect(await snapshot()).toEqual(before2)
      expect(readFileSync(replay, 'utf8')).toBe(db1Manifest)
    } finally {
      await otherClient.end()
      rmSync(otherManifest, { force: true })
      rmSync(replay, { force: true })
      await harness.dropDatabase(other)
    }
    await expectNoLingeringConnections()
  })

  test('a 0.7.0 manifest (signed, no database binding) needs --allow-unbound-manifest', async () => {
    const signed = readFileSync(manifestPath, 'utf8')
    const manifest = readManifestFile()
    // What migrate 0.7.0 wrote: version 3, the same MAC scheme, no binding.
    const legacy = signManifest(appSecret, {
      ...manifest,
      version: 3,
      databaseId: undefined,
      runId: undefined,
    })
    expect(legacy.version).toBe(3)
    const baBefore = await query('SELECT count(*)::int AS n FROM ba_users')
    try {
      writeFileSync(manifestPath, JSON.stringify(legacy))
      const refused = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
      expect(refused.code).toBe(1)
      expect(refused.err).toContain('--allow-unbound-manifest')
      expect(await query('SELECT count(*)::int AS n FROM ba_users')).toEqual(baBefore)
    } finally {
      writeFileSync(manifestPath, signed, { mode: 0o600 })
    }
  })

  test('an unreadable key-value store fails closed: nothing is deleted on the word of the file', async () => {
    const signed = readFileSync(manifestPath, 'utf8')
    const manifest = readManifestFile()
    const baBefore = await query('SELECT count(*)::int AS n FROM ba_users')
    await client.query('ALTER TABLE payload_kv RENAME TO payload_kv_hidden')
    try {
      // Signed, or unsigned with every opt-in: both refused.
      const genuine = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
      expect(genuine.code).toBe(1)
      expect(genuine.err).toContain('key-value store')
      writeFileSync(
        manifestPath,
        JSON.stringify({
          ...manifest,
          version: 2,
          mac: undefined,
          databaseId: undefined,
          runId: undefined,
        })
      )
      const unsigned = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
        '--allow-unsigned-deletes',
        '--allow-plaintext-restore',
      ])
      expect(unsigned.code).toBe(1)
      expect(unsigned.err).toContain('key-value store')
      expect(await query('SELECT count(*)::int AS n FROM ba_users')).toEqual(baBefore)
      await expectNoLingeringConnections()
    } finally {
      await client.query('ALTER TABLE payload_kv_hidden RENAME TO payload_kv')
      writeFileSync(manifestPath, signed, { mode: 0o600 })
    }
  })

  test('rollback with an unsigned manifest deletes nothing without --allow-unsigned-deletes', async () => {
    const signed = readFileSync(manifestPath, 'utf8')
    const manifest = readManifestFile()
    const downgraded = {
      ...manifest,
      version: 2,
      mac: undefined,
      databaseId: undefined,
      runId: undefined,
    }
    writeFileSync(manifestPath, JSON.stringify(downgraded))
    try {
      const baBefore = await query<{ n: number }>('SELECT count(*)::int AS n FROM ba_users')
      const refused = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
      ])
      expect(refused.code).toBe(1)
      expect(refused.err).toContain('--allow-unsigned-deletes')
      // A row injected into a host collection is refused even with both flags.
      writeFileSync(
        manifestPath,
        JSON.stringify({
          ...downgraded,
          created: [...manifest.created, { collection: 'users', id: 1, sourceKey: 'user:1' }],
        })
      )
      const injected = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        manifestPath,
        '--allow-unsigned-manifest',
        '--allow-unsigned-deletes',
      ])
      expect(injected.code).toBe(1)
      expect(injected.err).toContain("outside the import's target collections")
      expect(await query('SELECT count(*)::int AS n FROM ba_users')).toEqual(baBefore)
      expect(await query('SELECT id FROM users WHERE id = 1')).toEqual([{ id: 1 }])
      await expectNoLingeringConnections()
    } finally {
      writeFileSync(manifestPath, signed, { mode: 0o600 })
    }
  })

  test('a delete that fails aborts rollback non-zero, names the row, and keeps the manifest', async () => {
    const before = readFileSync(manifestPath, 'utf8')
    const hostUsers = await query('SELECT * FROM users ORDER BY id')
    const pinned = await query<{ id: number }>(
      "SELECT id FROM ba_users WHERE email = 'alice@example.com'"
    )
    const pinnedId = pinned[0]?.id
    expect(pinnedId).toBeDefined()
    // Something that references a ba_users row: its delete fails on the FK.
    await client.query(`
      CREATE TABLE rollback_fk_probe (ba_user_id integer REFERENCES ba_users(id));
      INSERT INTO rollback_fk_probe VALUES (${String(pinnedId)});
    `)
    try {
      const result = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
      expect(result.code).toBe(1)
      expect(result.err).toContain('could not delete 1')
      expect(result.err).toContain(`ba-users#${String(pinnedId)}`)
      // Nothing was restored and the manifest is intact for a re-run.
      expect(readFileSync(manifestPath, 'utf8')).toBe(before)
      expect(await query('SELECT * FROM users ORDER BY id')).toEqual(hostUsers)
      await expectNoLingeringConnections()
    } finally {
      await client.query('DROP TABLE rollback_fk_probe')
    }
  })

  test('rollback after two applies restores the host users exactly and resets the manifest', async () => {
    const preRollback = readFileSync(manifestPath, 'utf8')
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

    // The database closed the run: a copy of the pre-rollback manifest
    // (signed, same database) can never replay its captured values.
    const resetText = readFileSync(manifestPath, 'utf8')
    try {
      writeFileSync(manifestPath, preRollback)
      const replayed = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
      expect(replayed.code).toBe(1)
      expect(replayed.err).toContain('stale copy')
      expect((await hostSnapshot()).users).toEqual(before.users)
    } finally {
      writeFileSync(manifestPath, resetText, { mode: 0o600 })
    }
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

    // finalize boots the target app now: it signs and records the marker.
    const noConfig = await run(['finalize', '--manifest', manifestPath])
    expect(noConfig.code).toBe(3)
    expect(noConfig.err).toContain('--config')
    const preFinalize = readFileSync(manifestPath, 'utf8')

    const finalized = await run(['finalize', '--config', adminConfig, '--manifest', manifestPath])
    expect(finalized.code, finalized.err).toBe(0)
    expect(finalized.out).toContain('finalized: the manifest at')
    expect(finalized.out).toContain('legacy payload-auth tables may be dropped')
    await expectNoLingeringConnections()
    const sealed = readManifestFile()
    expect(sealed.finalized).toBe(true)
    expect(sealed.mac).toMatch(/^v2\./)
    const markers = await query<{ key: string }>(
      "SELECT key FROM payload_kv WHERE key LIKE 'payload-auth-link/migrate/finalized/%'"
    )
    expect(markers).toHaveLength(1)

    const baBefore = await query('SELECT count(*)::int AS n FROM ba_users')
    const finalizedText = readFileSync(manifestPath, 'utf8')
    try {
      // Flipping the flag breaks the signature.
      writeFileSync(manifestPath, JSON.stringify({ ...sealed, finalized: false }))
      const flipped = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
      expect(flipped.code).toBe(1)
      expect(flipped.err).toContain('integrity check')
      // The signed copy from BEFORE finalize: the database marker refuses it.
      writeFileSync(manifestPath, preFinalize)
      const stale = await run(['rollback', '--config', adminConfig, '--manifest', manifestPath])
      expect(stale.code).toBe(1)
      expect(stale.err).toContain('database records a finalized migration')
      await expectNoLingeringConnections()
    } finally {
      writeFileSync(manifestPath, finalizedText, { mode: 0o600 })
    }
    expect(await query('SELECT count(*)::int AS n FROM ba_users')).toEqual(baBefore)
  })

  test('GHSA-crrr case 2: on a finalized database, an unsigned manifest claiming adopt-prelink restores nothing', async () => {
    const sealed = readManifestFile()
    const hostBefore = await hostSnapshot()
    const disguised = join(tmpdir(), `pal-cli-disguised-${Date.now()}.json`)
    try {
      writeFileSync(
        disguised,
        JSON.stringify({
          version: 2,
          kind: 'adopt-prelink',
          createdAt: '2020-01-01T00:00:00.000Z',
          sourceDatabase: sealed.sourceDatabase,
          options: sealed.options,
          created: [],
          // The import's own sealed captures: genuine values, wrong run.
          fieldWrites: sealed.fieldWrites,
          finalized: false,
          sourceCounts: {},
          totals: {},
        })
      )
      const refused = await run([
        'rollback',
        '--config',
        adminConfig,
        '--manifest',
        disguised,
        '--allow-unsigned-manifest',
      ])
      expect(refused.code).toBe(1)
      expect(refused.err).toContain('records a finalized migration')
      expect(await hostSnapshot()).toEqual(hostBefore)
      await expectNoLingeringConnections()
    } finally {
      rmSync(disguised, { force: true })
    }
  })

  test('verify on an adopt-mode config says so instead of a misleading failure (#113)', async () => {
    const adopt = await run([
      'verify',
      '--config',
      adminConfig,
      '--database-url',
      url,
      '--slugs',
      JSON.stringify({ user: 'users' }),
    ])
    expect(adopt.code).toBe(1)
    expect(adopt.err).toContain('ADOPT mode')
    expect(adopt.err).toContain('Verifying an adopt cutover')
    expect(adopt.err).not.toContain('baId cannot be queried')
    await expectNoLingeringConnections()
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
