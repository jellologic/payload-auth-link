/**
 * Integration test: role-config safety across boots (B11, Phase 2).
 *
 * Boot A provisions users under roles ['admin', 'editor'] on a
 * file-backed SQLite database. Boot B removes 'editor' from
 * `authLink({ roles })` and must, before serving any request:
 * warn once, aggregating the drifted stored values, and stop
 * granting 'editor' in sessions — the admin-only user keeps a role,
 * while the editor-only user's record is denied (never upgraded to
 * the default role, matching the corrupt-roles policy).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { parseEmail, nullLogger, type Email, type LoggerPort } from '@payload-auth-link/core'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildConfig, getPayload, type Payload } from 'payload'
import { afterAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createServices } from '../services.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'roles-config-secret-32-chars!'

const dir = mkdtempSync(join(tmpdir(), 'pal-roles-config-'))
const dbUrl = `file:${join(dir, 'roles.db')}`

const stub = createStubProvider()

function rawOptions(roles: readonly string[], logger: LoggerPort): AuthLinkPluginOptions {
  return {
    baseUrl: ORIGIN,
    roles: [...roles],
    defaultRole: 'admin',
    providers: [stub.provider],
    logger,
  }
}

async function boot(key: string, options: AuthLinkPluginOptions): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: dbUrl }, push: true }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }],
    plugins: [authLink(options)],
  })
  return getPayload({ config, key })
}

function email(value: string): Email {
  const parsed = parseEmail(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

afterAll(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('role-config change between boots (B11)', () => {
  it('warns at startup and stops granting a removed role', async () => {
    const bootAWarnings: string[] = []
    const bootALogger: LoggerPort = {
      ...nullLogger(),
      warn: (message) => {
        bootAWarnings.push(message)
      },
      child: () => bootALogger,
    }
    const bootA = await boot('roles-config-a', rawOptions(['admin', 'editor'], bootALogger))
    await bootA.create({
      collection: 'users',
      data: {
        email: 'editor-only@test.dev',
        password: 'correct-horse-battery',
        roles: ['editor'],
        linkable: true,
      },
    })
    await bootA.create({
      collection: 'users',
      data: {
        email: 'admin-editor@test.dev',
        password: 'correct-horse-battery',
        roles: ['admin', 'editor'],
        linkable: true,
      },
    })
    await bootA.db.destroy?.()

    // Boot B: 'editor' removed from the configured set.
    const warnings: string[] = []
    const bootBLogger: LoggerPort = {
      ...nullLogger(),
      warn: (message) => {
        warnings.push(message)
      },
      child: () => bootBLogger,
    }
    const optionsB = rawOptions(['admin'], bootBLogger)
    const bootB = await boot('roles-config-b', optionsB)

    const auditWarnings = warnings.filter((message) => message.includes('outside the configured'))
    expect(auditWarnings).toHaveLength(1)
    expect(auditWarnings[0]).toContain("'editor' (2)")

    // Sessions never grant the removed role again: same wiring the
    // strategy and endpoints build per request.
    const { users } = createServices(wireOptions(optionsB), bootB)
    const denied = await users.findByEmail(email('editor-only@test.dev'))
    expect(denied.isOk() && denied.value).toBeNull()
    const kept = await users.findByEmail(email('admin-editor@test.dev'))
    expect(kept.isOk() && kept.value?.roles).toEqual(['admin'])

    await bootB.db.destroy?.()
  }, 120_000)
})
