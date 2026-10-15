// @vitest-environment happy-dom
/**
 * The payload.betterAuth compatibility shim (issue #53): backed by
 * authLinkServer, deprecation-warned once, no back door (the
 * suspension gate applies through the server API).
 */
import { nullLogger } from '@payload-auth-link/core'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildConfig, getPayload } from 'payload'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { authLink } from '../index.js'
import { createBetterAuthCompatShim } from '../compat-shim.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createServices } from '../services.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const stub = createStubProvider()

const options: AuthLinkPluginOptions = {
  baseUrl: ORIGIN,
  roles: ['user', 'admin'],
  defaultRole: 'user',
  roleManagerRoles: ['admin'],
  providers: [stub.provider],
  logger: nullLogger(),
}

const dir = mkdtempSync(join(tmpdir(), 'pal-shim-'))

describe('payload.betterAuth compatibility shim (issue #53)', () => {
  it('delegates getSession to the supported server API and warns once', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const config = await buildConfig({
      secret: 'shim-secret-shim-secret-shim-secret',
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapterShim(),
      collections: [{ slug: 'users', auth: true, fields: [] }],
      plugins: [authLink(options)],
    })
    const payload = await getPayload({ config, key: 'shim-a' })
    const services = createServices(wireOptions(options), payload)
    const { parseEmail, parseRole } = await import('@payload-auth-link/core')
    const email = parseEmail('shim@test.dev')
    const role = parseRole('user')
    expect(email.isOk() && role.isOk()).toBe(true)
    if (email.isErr() || role.isErr()) {
      throw new Error('unreachable')
    }
    const created = await services.users.create({
      email: email.value,
      roles: [role.value],
    })
    expect(created.isOk(), created.isErr() ? 'create failed' : 'ok').toBe(true)
    if (!created.isOk()) {
      throw new Error('unreachable')
    }

    const shim = createBetterAuthCompatShim(payload)
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toContain('DEPRECATED')

    const cookie = stub.issue({
      sessionId: 'shim-s1',
      providerUserId: 'stub-1',
      email: 'shim@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const session = await shim.api.getSession({ headers: new Headers({ cookie }) })
    expect((session as { id?: unknown } | null)?.id).toBe(String(created.value.id))
    // Second construction: still exactly one warning (warn-once per process).
    createBetterAuthCompatShim(payload)
    expect(warn).toHaveBeenCalledTimes(1)
    warn.mockRestore()
  })

  it('the shim has no back door: a suspended user gets null like the server API', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const config = await buildConfig({
      secret: 'shim-secret-shim-secret-shim-secret',
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapterShim(),
      collections: [{ slug: 'users', auth: true, fields: [] }],
      plugins: [authLink(options)],
    })
    const payload = await getPayload({ config, key: 'shim-b' })
    const services = createServices(wireOptions(options), payload)
    const { parseEmail, parseRole } = await import('@payload-auth-link/core')
    const email = parseEmail('shim-susp@test.dev')
    const role = parseRole('user')
    expect(email.isOk() && role.isOk()).toBe(true)
    if (email.isErr() || role.isErr()) {
      throw new Error('unreachable')
    }
    const created = await services.users.create({
      email: email.value,
      roles: [role.value],
    })
    expect(created.isOk(), created.isErr() ? 'create failed' : 'ok').toBe(true)
    if (!created.isOk()) {
      throw new Error('unreachable')
    }
    await payload.update({
      collection: 'users',
      id: created.value.id,
      data: { suspendedUntil: new Date(Date.now() + 86_400_000).toISOString() },
      overrideAccess: true,
    })
    const shim = createBetterAuthCompatShim(payload)
    const cookie = stub.issue({
      sessionId: 'shim-s2',
      providerUserId: 'stub-2',
      email: 'shim-susp@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const session = await shim.api.getSession({ headers: new Headers({ cookie }) })
    // The strategies' suspension gate refuses the session entirely.
    expect(session).toBeNull()
    warn.mockRestore()
  })

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true })
  })
})

function sqliteAdapterShim() {
  return sqliteAdapter({ client: { url: `file:${join(dir, 'shim.db')}` }, push: true })
}
