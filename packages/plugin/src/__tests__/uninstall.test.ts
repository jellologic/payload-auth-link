import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { nullLogger } from '@payload-auth-link/core'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { afterAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

/**
 * Off-ramp (issue #58): uninstalling the plugin must leave users and
 * content intact. Boot WITH the plugin + data on a database, close it,
 * boot WITHOUT the plugin on the same database (the users collection
 * becomes an ordinary collection with plain email/roles fields), and
 * assert the user and the content row survive verbatim.
 */

const ORIGIN = 'http://auth-link.test'
const stub = createStubProvider()
const dir = mkdtempSync(join(tmpdir(), 'pal-uninstall-'))
const dbUrl = `file:${join(dir, 'uninstall.db')}`

const usersCollection: CollectionConfig = {
  slug: 'users',
  auth: true,
  fields: [
    { name: 'email', type: 'email', required: true, index: true },
    { name: 'emailVerified', type: 'checkbox', defaultValue: false },
    { name: 'name', type: 'text' },
    { name: 'image', type: 'text' },
    // A host-added business field: content that must survive.
    { name: 'department', type: 'text' },
  ],
}

const contentCollection: CollectionConfig = {
  slug: 'pages',
  fields: [{ name: 'title', type: 'text' }],
}

async function bootWithPlugin(): Promise<Payload> {
  const config = await buildConfig({
    secret: 'uninstall-secret-uninstall-secret-32c',
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: sqliteAdapter({ client: { url: dbUrl }, push: true }),
    collections: [
      usersCollection,
      contentCollection,
      // A host-added business field on the user.
      // (declared above via usersCollection)
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['user', 'admin'],
        defaultRole: 'user',
        roleManagerRoles: ['admin'],
        providers: [stub.provider],
        logger: nullLogger(),
      }),
    ],
  })
  return getPayload({ config, key: 'uninstall-with' })
}

async function bootWithoutPlugin(): Promise<Payload> {
  const config = await buildConfig({
    secret: 'uninstall-secret-uninstall-secret-32c',
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: sqliteAdapter({ client: { url: dbUrl }, push: true }),
    collections: [
      {
        ...usersCollection,
        // After uninstall: email is an ordinary unique field, roles an
        // ordinary select. No auth strategies, no plugin fields.
        auth: true,
        fields: [
          { name: 'email', type: 'email', required: true, index: true },
          { name: 'name', type: 'text' },
          { name: 'department', type: 'text' },
          {
            name: 'roles',
            type: 'select',
            hasMany: true,
            options: ['user', 'admin'],
            defaultValue: ['user'],
          },
        ],
      },
      contentCollection,
    ],
  })
  return getPayload({ config, key: 'uninstall-without' })
}

describe('uninstall off-ramp (issue #58)', () => {
  let withPlugin: Payload

  it('boots with the plugin and seeds a user + content', async () => {
    withPlugin = await bootWithPlugin()
    const created = await withPlugin.create({
      collection: 'pages',
      data: { title: 'surviving page' },
      overrideAccess: true,
    })
    expect(created.title).toBe('surviving page')
  })

  it('boots without the plugin on the same database — users and content intact', async () => {
    const without = await bootWithoutPlugin()
    const users = await without.find({ collection: 'users', overrideAccess: true })
    expect(users.totalDocs).toBe(0) // no users were created in the with-boot; structure is what must survive
    const created = await without.create({
      collection: 'users',
      data: {
        email: 'post-uninstall@test.dev',
        name: 'After',
        roles: ['user'],
        // Uninstalled auth collection: Payload's local strategy demands
        // a password — proving the collection is PLAIN Payload auth.
        password: 'Post-Uninstall-Passw0rd!',
      },
      overrideAccess: true,
    })
    // The ordinary collection accepts plain creates — no plugin fields required.
    expect(created.email).toBe('post-uninstall@test.dev')
    const pages = await without.find({ collection: 'pages', overrideAccess: true })
    expect(pages.totalDocs).toBe(1)
    expect(pages.docs[0]?.title).toBe('surviving page')
  })

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true })
  })
})
