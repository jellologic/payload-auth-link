import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { dropDatabase, fixtureClient, loadFixtureDump, targetFromEnv } from './harness.js'
import { introspectDatabase } from '../../../packages/migrate/src/doctor/database.js'
import { runDoctor } from '../../../packages/migrate/src/doctor/run-doctor.js'

/**
 * Doctor database introspection against the real fixture dump
 * (issue #52): row counts, unverified users, zero orphans. Postgres
 * is required — the suite skips when no fixture Postgres is reachable,
 * and always runs in the migration-fixture CI job.
 */
const canReachPostgres = await (async () => {
  try {
    const client = fixtureClient('postgres')
    await client.connect()
    await client.end()
    return true
  } catch {
    return false
  }
})()

describe.skipIf(!canReachPostgres)('doctor: database introspection', () => {
  let database: string
  beforeAll(async () => {
    database = await loadFixtureDump('pal_doctor')
  }, 60_000)
  afterAll(async () => {
    await dropDatabase(database)
  })

  test('counts every payload-auth table and finds the unverified users', async () => {
    const { password, port, user } = targetFromEnv(database)
    const databaseUrl = `postgres://${user}:${password}@localhost:${port}/${database}`
    const finding = await introspectDatabase(databaseUrl)
    const byName = new Map(finding.tables.map((table) => [table.name, table.rows]))
    expect(byName.get('users')).toBe(4)
    expect(byName.get('accounts')).toBe(6)
    expect(byName.get('sessions')).toBe(6)
    expect(byName.get('verifications')).toBe(1)
    expect(byName.get('api_keys')).toBe(2)
    expect(byName.get('organizations')).toBe(2)
    expect(byName.get('members')).toBe(3)
    expect(byName.get('invitations')).toBe(2)
    expect(byName.get('jwks')).toBe(1)
    expect(byName.get('users_role')).toBe(5)
    expect(finding.unverifiedUsers).toBe(2)
    expect(finding.orphans).toEqual([])
  })

  test(
    'the doctor flags unverified users as the JIT-link risk',
    // A cold CI cache pays the whole fixture dependency transform once.
    { timeout: 300_000 },
    async () => {
      // In-process on purpose: the config import must resolve the
      // fixture app's own dependency tree (vite transforms it), and a
      // spawned `bun cli.ts` cannot resolve the kit's workspace imports
      // from a fresh CI checkout (bun's isolated-install symlinks are
      // invisible to its own ESM resolver there).
      const { password, port, user } = targetFromEnv(database)
      const databaseUrl = `postgres://${user}:${password}@localhost:${port}/${database}`
      const report = await runDoctor({
        configPath: new URL('../payload.config.ts', import.meta.url).pathname,
        srcDir: new URL('../src', import.meta.url).pathname,
        databaseUrl,
      })
      expect(report.database?.unverifiedUsers).toBe(2)
      expect(report.warnings.map((issue) => issue.code)).toContain('unverified-users')
      // Orphans would be blockers; the fixture is clean.
      expect(report.blockers.map((issue) => issue.code)).not.toContain('orphan-rows')
    }
  )
})
