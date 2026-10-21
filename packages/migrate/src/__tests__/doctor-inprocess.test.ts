import { fileURLToPath } from 'node:url'
import { describe, expect, test } from 'vitest'
import { cliMain } from '../cli.js'
import { runDoctor } from '../doctor/run-doctor.js'
import type { DoctorReport } from '../doctor/types.js'

/**
 * The doctor end to end, IN-PROCESS: runDoctor against the real
 * fixture app (issue #52 acceptance — the exact blocker list), and
 * `cliMain` with injected sinks (arg parsing, exit codes, output
 * format). The fixture config loads through the app's own dependency
 * tree, so the first import transforms payload-auth under Vite; the
 * suite budget allows for that one-time cost.
 */

const fixtureRoot = fileURLToPath(
  new URL('../../../../fixtures/payload-auth-app/', import.meta.url)
)
const fixtureConfigPath = `${fixtureRoot}payload.config.ts`

// The specifier stays a runtime-computed path so the typecheck project
// never reaches into fixtures/ (the fixture app has its own dependency
// tree and lint profile).
const loadFixtureConfig = async (path: string): Promise<unknown> => {
  const mod = (await import(path)) as { default: unknown }
  let config: unknown = mod.default
  if (typeof (config as Partial<Promise<unknown>> | undefined)?.then === 'function') {
    config = await config
  }
  return config
}

// The fixture app owns its dependency tree (it mirrors an unmigrated
// payload-auth app), so its node_modules are installed separately (the
// test:fixture script and the migration-fixture CI job do it). When
// they are absent — a bare `bun run check` — the fixture-backed tests
// skip instead of failing on the unresolvable imports.
const canLoadFixture = await (async () => {
  try {
    await import(fixtureConfigPath)
    return true
  } catch {
    return false
  }
})()

describe.skipIf(!canLoadFixture)('doctor: in-process fixture report (exact blocker list)', () => {
  let report: DoctorReport
  test('runDoctor lists exactly the blockers the importer would hit', async () => {
    report = await runDoctor({
      configPath: fixtureConfigPath,
      srcDir: `${fixtureRoot}src`,
      databaseUrl: '',
      loadModule: loadFixtureConfig,
    })
    expect(report.blockers.map((issue) => issue.code)).toEqual([
      'better-auth-out-of-band',
      'payload-auth-installed',
      'ba-internals-usage',
    ])
    expect(report.warnings.map((issue) => issue.code)).toEqual([
      // The fixture IS the failing combo (#156): payload-auth 1.9.4 on
      // better-auth 1.6.30, so the hook-stacking warning fires first.
      'payload-auth-hook-stacking',
      // payload-auth's session collection has no authenticationMethod
      // field; adopting it as-is records no MFA provenance (#116).
      'adopt-session-no-authentication-method',
      'non-canonical-role-value',
      'database-not-inspected',
    ])
    expect(
      report.warnings.find((issue) => issue.code === 'payload-auth-hook-stacking')?.detail
    ).toContain('res.session.userId')
    expect(
      report.warnings.find((issue) => issue.code === 'adopt-session-no-authentication-method')
        ?.detail
    ).toContain("'sessions'")
    const byId = new Map(report.plugins.map((finding) => [finding.id, finding.status]))
    expect(byId.get('api-key')).toBe('supported')
    expect(byId.get('organization')).toBe('auto-declarable')
    expect(byId.get('magic-link')).toBe('auto-declarable')
    expect(report.users?.roleField?.nonCanonical).toEqual(['frontPlugin'])
    // The source layout, read off payload-auth's own collections (#113):
    // the fixture keeps the default tables, so no --source-map is needed.
    expect(report.sourceMap).toEqual({
      users: 'users',
      accounts: 'accounts',
      sessions: 'sessions',
      verifications: 'verifications',
      api_keys: 'api_keys',
      jwks: 'jwks',
      organizations: 'organizations',
      members: 'members',
      invitations: 'invitations',
      users_role: 'users_role',
    })
    const kinds = new Map(report.source.map((finding) => [finding.kind, finding]))
    expect(kinds.get('ba-internals')?.files).toEqual(['lib/api-key-bridge.ts'])
    expect(kinds.get('req-user-field')?.fields.toSorted()).toEqual(['activeOrganization', 'name'])
    expect(JSON.stringify(report.source)).not.toContain('fine.ts')
    const betterAuth = report.versions.find((finding) => finding.name === 'better-auth')
    expect(betterAuth?.installed).toBe('1.6.30')
    expect(betterAuth?.status).toBe('blocker')
  }, 180_000)

  test('cliMain exits 1 with JSON output and 3 on usage errors', async () => {
    const chunks: string[] = []
    const sink = {
      write: (chunk: string): void => {
        chunks.push(chunk)
      },
    }
    const code = await cliMain(
      ['doctor', '--config', fixtureConfigPath, '--src', `${fixtureRoot}src`, '--json'],
      sink,
      sink
    )
    expect(code).toBe(1)
    const printed = JSON.parse(chunks.join('')) as DoctorReport
    expect(printed.blockers.length).toBe(3)
    const badCommand: string[] = []
    await expect(
      cliMain(['nonsense'], sink, {
        write: (c) => {
          badCommand.push(c)
        },
      })
    ).resolves.toBe(3)
    expect(badCommand.join('')).toContain('unknown command')
    await expect(cliMain(['doctor'], sink, sink)).resolves.toBe(3)
    await expect(cliMain(['--help'], sink, sink)).resolves.toBe(0)
  }, 180_000)
})
