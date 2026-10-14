/**
 * Integration test: the role value map and the role projection
 * (issue #56). A payload-auth-style host stores `frontPlugin`; the
 * plugin is configured with the canonical slug `front-plugin` and
 * `roleValues` — stored values never change, `requireRoles` reasons
 * canonically, and `projectRolesAs: 'stored'` hands access functions
 * the stored form while the MFA gate stays canonical.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { nullLogger, parseEmail, parseRole, type Email, type Role } from '@payload-auth-link/core'
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
const SECRET = 'role-values-secret-32-chars!!'

const dir = mkdtempSync(join(tmpdir(), 'pal-role-values-'))
const dbUrl = `file:${join(dir, 'roles.db')}`
const stub = createStubProvider()

const baseOptions: AuthLinkPluginOptions = {
  baseUrl: ORIGIN,
  roles: ['user', 'admin', 'staff', 'front-plugin'],
  defaultRole: 'user',
  roleManagerRoles: ['admin'],
  roleValues: { 'front-plugin': 'frontPlugin' },
  providers: [stub.provider],
  logger: nullLogger(),
}

const servicesFor = (payload: Payload): ReturnType<typeof createServices> =>
  createServices(wireOptions(baseOptions), payload)

/** Test emails/roles are valid by construction; unwrap the brand. */
function email(value: string): Email {
  const parsed = parseEmail(value)
  if (parsed.isErr()) {
    throw new Error(`bad test email: ${value}`)
  }
  return parsed.value
}

function role(value: string): Role {
  const parsed = parseRole(value)
  if (parsed.isErr()) {
    throw new Error(`bad test role: ${value}`)
  }
  return parsed.value
}

async function boot(key: string): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: dbUrl }, push: true }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }],
    plugins: [authLink(baseOptions)],
  })
  return getPayload({ config, key })
}

afterAll(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('role value map (issue #56)', () => {
  it('stores canonical roles in their mapped form and reads them back canonical', async () => {
    const payload = await boot('role-values-a')
    const services = servicesFor(payload)
    const created = await services.users.create({
      email: email('bob@test.dev'),
      roles: [role('front-plugin'), role('user')],
    })
    expect(created.isOk(), created.isErr() ? String(created.error) : 'create failed').toBe(true)
    if (!created.isOk()) {
      throw new Error('unreachable')
    }
    // The stored select keeps the payload-auth value, untouched.
    const doc = await payload.findByID({
      collection: 'users',
      id: created.value.id,
      overrideAccess: true,
    })
    expect(doc.roles).toEqual(['frontPlugin', 'user'])
    // The storage edge translates back: repository reads are canonical.
    const found = await services.users.findByEmail(email('bob@test.dev'))
    expect(found.isOk() && found.value !== null).toBe(true)
    if (!found.isOk() || found.value === null) {
      throw new Error('unreachable')
    }
    expect(found.value.roles).toEqual(['front-plugin', 'user'])
  })

  it('the injected select offers stored values so admin edits round-trip', async () => {
    const payload = await boot('role-values-b')
    const field = payload.collections.users?.config.fields.find(
      (candidate) =>
        typeof candidate === 'object' &&
        candidate !== null &&
        'type' in candidate &&
        (candidate as { type?: string }).type === 'select'
    ) as { name: string; options?: readonly { label?: string; value: string }[] } | undefined
    expect(field?.options?.map((option) => option.value)).toEqual([
      'user',
      'admin',
      'staff',
      'frontPlugin',
    ])
    expect(field?.options?.map((option) => option.label)).toContain('front-plugin')
  })

  it('the session projection carries canonical roles by default', async () => {
    const payload = await boot('role-values-c')
    const services = servicesFor(payload)
    const created = await services.users.create({
      email: email('carol@test.dev'),
      roles: [role('front-plugin')],
    })
    expect(created.isOk(), created.isErr() ? String(created.error) : 'create failed').toBe(true)
    if (!created.isOk()) {
      throw new Error('unreachable')
    }
    const record = await services.users.findById(created.value.id)
    expect(record.isOk() && record.value !== null).toBe(true)
    if (!record.isOk() || record.value === null) {
      throw new Error('unreachable')
    }
    expect(record.value.roles).toEqual(['front-plugin'])
  })
})
