import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { dropDatabase, fixtureClient, loadFixtureDump, targetFromEnv } from './harness.js'
import { spawn } from 'node:child_process'
import { introspectDatabase } from '../../../packages/migrate/src/doctor/database.js'
import type { DoctorReport } from '../../../packages/migrate/src/doctor/types.js'

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

  test('the doctor flags unverified users as the JIT-link risk', async () => {
    // Through the CLI, like an app runs it: the config import must
    // resolve the fixture app's own dependency tree.
    const { password, port, user } = targetFromEnv(database)
    const databaseUrl = `postgres://${user}:${password}@localhost:${port}/${database}`
    const cliPath = new URL('../../../packages/migrate/src/cli.ts', import.meta.url).pathname
    const configPath = new URL('../payload.config.ts', import.meta.url).pathname
    const report = await new Promise<DoctorReport>((resolvePromise, reject) => {
      const child = spawn('bun', [cliPath, 'doctor', '--config', configPath, '--json'], {
        cwd: process.cwd(),
        env: { ...process.env, DATABASE_URL: databaseUrl },
      })
      let stdout = ''
      child.stdout.on('data', (chunk: Buffer) => {
        stdout += String(chunk)
      })
      child.on('error', reject)
      child.on('close', () => {
        const start = stdout.indexOf('{')
        resolvePromise(JSON.parse(stdout.slice(start)) as DoctorReport)
      })
    })
    expect(report.database?.unverifiedUsers).toBe(2)
    expect(report.warnings.map((issue) => issue.code)).toContain('unverified-users')
    // Orphans would be blockers; the fixture is clean.
    expect(report.blockers.map((issue) => issue.code)).not.toContain('orphan-rows')
  })
})
