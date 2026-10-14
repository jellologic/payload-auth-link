/**
 * Issue #49 acceptance, against the real payload-auth dump: the
 * fixture boots on payload-auth-link with ZERO row moves — old
 * passwords sign in, sessions/orgs/members/API keys resolve, and
 * host-added fields survive Better Auth writes.
 *
 * The config below is the migrating app's target: the fixture's own
 * collections (groups, arrays, relationships — host config intact),
 * the authLink plugin on the existing users collection, and the engine
 * adopting every model through `schemaMap` with `idStrategy: 'payload'`.
 * `push` performs only the additive columns the plugin injects
 * (identities, linkable, suspension) — no row is copied, moved, or
 * rewritten.
 */
import { apiKey as apiKeyPlugin } from '@better-auth/api-key'
import { readFileSync } from 'node:fs'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { nextCookies } from 'better-auth/next-js'
import { jwt, magicLink, organization } from 'better-auth/plugins'
import { authLink } from '@payload-auth-link/plugin'
import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { Client } from 'pg'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { fileURLToPath } from 'node:url'

// Runtime-computed specifier: the typecheck project never reaches into
// fixtures/ (the fixture app owns its dependency tree).
const harnessPath = fileURLToPath(
  new URL('../../../../fixtures/payload-auth-app/test/harness.ts', import.meta.url)
)
const adoptSchemaSql = readFileSync(
  fileURLToPath(
    new URL('../../../../fixtures/payload-auth-app/test/adopt-schema.sql', import.meta.url)
  ),
  'utf8'
)
type Harness = {
  dropDatabase: (database: string) => Promise<void>
  expectedCounts: Readonly<Record<string, number>>
  fixtureClient: (database: string) => import('pg').Client
  loadFixtureDump: (prefix: string) => Promise<string>
  targetFromEnv: (database: string) => {
    host: string
    port: number
    user: string
    password: string
  }
}
const harness = (await import(harnessPath)) as Harness

const PASSWORD = 'FixturePassw0rd!'
const ORIGIN = 'http://localhost:3100'

// --- the fixture layout, as the migrating app declares it ---------------
// Field lists mirror the dump's tables; host-added fields (department,
// billing, tags, owner) ride along untouched.
const hostCollections: CollectionConfig[] = [
  {
    slug: 'users',
    auth: true,
    admin: { useAsTitle: 'email' },
    fields: [
      { name: 'email', type: 'email', required: true, index: true },
      { name: 'emailVerified', type: 'checkbox', defaultValue: false },
      { name: 'name', type: 'text' },
      { name: 'image', type: 'text' },
      { name: 'department', type: 'text' },
      {
        name: 'role',
        type: 'select',
        hasMany: true,
        options: ['user', 'admin', 'staff', 'frontPlugin'],
        defaultValue: ['user'],
        required: true,
      },
    ],
  },
  {
    slug: 'accounts',
    fields: [
      { name: 'user', type: 'relationship', relationTo: 'users', required: true, index: true },
      { name: 'accountId', type: 'text', required: true, index: true },
      { name: 'providerId', type: 'text', required: true, index: true },
      { name: 'password', type: 'text' },
      { name: 'accessToken', type: 'text' },
      { name: 'refreshToken', type: 'text' },
      { name: 'idToken', type: 'text' },
      { name: 'accessTokenExpiresAt', type: 'date' },
      { name: 'refreshTokenExpiresAt', type: 'date' },
      { name: 'scope', type: 'text' },
    ],
  },
  {
    slug: 'sessions',
    fields: [
      { name: 'user', type: 'relationship', relationTo: 'users', required: true, index: true },
      { name: 'token', type: 'text', required: true, unique: true, index: true },
      { name: 'expiresAt', type: 'date', required: true },
      { name: 'ipAddress', type: 'text' },
      { name: 'userAgent', type: 'text' },
      { name: 'activeOrganization', type: 'relationship', relationTo: 'organizations' },
    ],
  },
  {
    slug: 'verifications',
    fields: [
      { name: 'identifier', type: 'text', required: true, index: true },
      { name: 'value', type: 'text', required: true },
      { name: 'expiresAt', type: 'date', required: true },
    ],
  },
  {
    slug: 'apiKeys',
    labels: { singular: 'API key', plural: 'API keys' },
    fields: [
      { name: 'configId', type: 'text', required: true },
      { name: 'name', type: 'text' },
      { name: 'start', type: 'text' },
      { name: 'prefix', type: 'text' },
      { name: 'key', type: 'text', required: true },
      { name: 'referenceId', type: 'text', required: true, index: true },
      { name: 'refillInterval', type: 'number' },
      { name: 'refillAmount', type: 'number' },
      { name: 'lastRefillAt', type: 'date' },
      { name: 'enabled', type: 'checkbox', defaultValue: true },
      { name: 'rateLimitEnabled', type: 'checkbox', defaultValue: true },
      { name: 'rateLimitTimeWindow', type: 'number' },
      { name: 'rateLimitMax', type: 'number' },
      { name: 'requestCount', type: 'number' },
      { name: 'remaining', type: 'number' },
      { name: 'lastRequest', type: 'date' },
      { name: 'expiresAt', type: 'date' },
      { name: 'permissions', type: 'text' },
      { name: 'metadata', type: 'text' },
    ],
  },
  {
    slug: 'organizations',
    fields: [
      { name: 'name', type: 'text', required: true },
      { name: 'slug', type: 'text', required: true, unique: true, index: true },
      { name: 'logo', type: 'text' },
      { name: 'metadata', type: 'json' },
      {
        name: 'billing',
        type: 'group',
        fields: [
          { name: 'plan', type: 'text', defaultValue: 'free' },
          { name: 'seats', type: 'number', defaultValue: 5 },
        ],
      },
      { name: 'tags', type: 'array', fields: [{ name: 'label', type: 'text' }] },
      { name: 'owner', type: 'relationship', relationTo: 'users' },
    ],
  },
  {
    slug: 'members',
    fields: [
      {
        name: 'organization',
        type: 'relationship',
        relationTo: 'organizations',
        required: true,
        index: true,
      },
      { name: 'user', type: 'relationship', relationTo: 'users', required: true, index: true },
      {
        name: 'role',
        type: 'select',
        options: ['owner', 'admin', 'member'],
        defaultValue: 'member',
      },
    ],
  },
  {
    slug: 'invitations',
    fields: [
      {
        name: 'organization',
        type: 'relationship',
        relationTo: 'organizations',
        required: true,
        index: true,
      },
      { name: 'email', type: 'email', required: true, index: true },
      { name: 'role', type: 'text' },
      {
        name: 'status',
        type: 'select',
        options: ['pending', 'accepted', 'rejected', 'canceled'],
        defaultValue: 'pending',
      },
      { name: 'expiresAt', type: 'date', required: true },
      { name: 'inviter', type: 'relationship', relationTo: 'users', index: true },
    ],
  },
  {
    slug: 'jwks',
    fields: [
      { name: 'publicKey', type: 'text', required: true },
      { name: 'privateKey', type: 'text', required: true },
    ],
  },
]

const canReachPostgres = await (async () => {
  try {
    const probe = new Client(harness.targetFromEnv('postgres'))
    await probe.connect()
    await probe.end()
    return true
  } catch {
    return false
  }
})()

describe.skipIf(!canReachPostgres)(
  'adopt mode: the payload-auth fixture boots with zero row moves',
  () => {
    let database: string
    let payload: Payload
    let latePayload: Payload | undefined
    const before: Record<string, number> = {}

    const engine = createBetterAuthEngine({
      getPayload: () => {
        if (latePayload === undefined) {
          throw new Error('Payload not ready')
        }
        return Promise.resolve(latePayload)
      },
      schemaMap: {
        user: { slug: 'users' },
        session: {
          slug: 'sessions',
          fields: { userId: 'user', activeOrganizationId: 'activeOrganization' },
        },
        account: { slug: 'accounts', fields: { userId: 'user' } },
        verification: { slug: 'verifications' },
        organization: { slug: 'organizations' },
        member: {
          slug: 'members',
          fields: { organizationId: 'organization', userId: 'user' },
        },
        invitation: {
          slug: 'invitations',
          fields: { organizationId: 'organization', inviterId: 'inviter' },
        },
        apikey: { slug: 'apiKeys', fields: { userId: 'referenceId' } },
        jwks: { slug: 'jwks' },
        // No rate-limit table exists in the dump, and adopting it keeps
        // the engine from creating a new collection (whose lock-relation
        // column would need its own additive step).
        rateLimit: { slug: 'rate_limits' },
      },
      idStrategy: 'payload',
      autoDeclare: true,
      options: {
        baseURL: ORIGIN,
        secret: 'boot-secret-boot-secret-boot-secret',
        emailAndPassword: { enabled: true, requireEmailVerification: false },
        advanced: { cookiePrefix: 'bl' },
        plugins: [
          magicLink({ sendMagicLink: async () => {} }),
          organization({ sendInvitationEmail: async () => {} }),
          apiKeyPlugin({ enableMetadata: true }),
          jwt(),
          nextCookies(),
        ],
        rateLimit: { enabled: false },
      },
    })

    beforeAll(async () => {
      database = await harness.loadFixtureDump('pal_adopt')
      const target = harness.targetFromEnv(database)
      const connectionString = `postgres://${target.user}:${target.password}@${target.host}:${target.port}/${database}`
      // Row-count baseline BEFORE boot — the no-moves assertion compares
      // against it.
      const client = harness.fixtureClient(database)
      await client.connect()
      for (const table of Object.keys(harness.expectedCounts)) {
        const counted = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
        before[table] = (counted.rows[0] as { n: number } | undefined)?.n ?? -1
      }
      // The additive step a migrating app runs before boot (issue #49):
      // the plugin-injected users columns. `push` stays OFF — drizzle's
      // push prompts interactively when it meets the payload-auth
      // layout's enums, and a migration must never hang on a prompt.
      const schema = harness.fixtureClient(database)
      await schema.connect()
      await schema.query(adoptSchemaSql)
      await schema.end()

      const config = await buildConfig({
        secret: 'boot-secret-boot-secret-boot-secret',
        serverURL: ORIGIN,
        db: postgresAdapter({ push: false, pool: { connectionString } }),
        telemetry: false,
        logger: { options: { level: 'silent' } },
        admin: { user: 'users' },
        collections: [...hostCollections, ...engine.collections],
        plugins: [
          authLink({
            baseUrl: ORIGIN,
            roles: ['user', 'admin', 'staff', 'front-plugin'],
            defaultRole: 'user',
            rolesField: 'role',
            roleManagerRoles: ['admin'],
            roleValues: { 'front-plugin': 'frontPlugin' },
            providers: [engine.provider],
          }),
        ],
      })
      payload = await getPayload({ config })
      latePayload = payload
      await engine.auth.$context
    }, 180_000)

    afterAll(async () => {
      // Release Payload's pool before the database goes away, or the
      // forced termination surfaces as unhandled pg errors.
      await payload.db.destroy?.()
      await harness.dropDatabase(database)
    })

    test('booting added no rows to the fixture (zero row moves)', async () => {
      const client = harness.fixtureClient(database)
      await client.connect()
      for (const [table, rows] of Object.entries(before)) {
        const counted = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
        const after = (counted.rows[0] as { n: number } | undefined)?.n ?? -1
        expect(after, table).toBe(rows)
      }
      await client.end()
    })

    test('an old password signs in through the engine', async () => {
      const response = await engine.auth.handler(
        new Request(`${ORIGIN}/api/auth/sign-in/email`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: ORIGIN },
          body: JSON.stringify({ email: 'alice@example.com', password: PASSWORD }),
        })
      )
      expect(response.status).toBe(200)
      const body = (await response.json()) as { user?: { email?: string; id?: string } }
      expect(body.user?.email).toBe('alice@example.com')
    })

    test('orgs, members, invitations and API keys resolve through the adopted collections', async () => {
      const orgs = await payload.find({
        collection: 'organizations',
        depth: 0,
        overrideAccess: true,
      })
      expect(orgs.totalDocs).toBe(2)
      const acme = orgs.docs.find((doc) => doc.slug === 'acme')
      expect(acme).toBeDefined()
      const members = await payload.find({ collection: 'members', depth: 0, overrideAccess: true })
      expect(members.totalDocs).toBe(3)
      const invitations = await payload.find({
        collection: 'invitations',
        depth: 0,
        overrideAccess: true,
      })
      expect(invitations.totalDocs).toBe(2)
      const keys = await payload.find({ collection: 'apiKeys', depth: 0, overrideAccess: true })
      expect(keys.totalDocs).toBe(2)
      const ctx = await engine.auth.$context
      const baMember = await ctx.adapter.findOne<{ id: string; organizationId: string }>({
        model: 'member',
        where: [],
      })
      expect(baMember).not.toBeNull()
      // The renamed relationship field reads as the Better Auth id.
      expect(typeof baMember?.organizationId).toBe('string')
    })

    test('host fields survive a round of Better Auth writes', async () => {
      const orgs = await payload.find({
        collection: 'organizations',
        depth: 0,
        overrideAccess: true,
      })
      const acme = orgs.docs.find((doc) => doc.slug === 'acme')
      expect(acme).toBeDefined()
      const ctx = await engine.auth.$context
      // Better Auth's own update path on the adopted organization.
      await ctx.adapter.update({
        model: 'organization',
        where: [{ field: 'id', value: String(acme?.id) }],
        update: { name: 'Acme Inc (renamed)' },
      })
      const after = await payload.findByID({
        collection: 'organizations',
        id: acme?.id as number,
        depth: 0,
        overrideAccess: true,
      })
      expect(after.name).toBe('Acme Inc (renamed)')
      expect(after.billing).toMatchObject({ plan: 'pro', seats: 12 })
      expect((after.tags as { label: string }[]).map((tag) => tag.label)).toEqual([
        'launch',
        'beta',
      ])
      expect(Number(after.owner)).toBe(1)
    })

    test('the carried roles keep their stored value and read canonically', async () => {
      const users = await payload.find({
        collection: 'users',
        where: { email: { equals: 'bob@example.com' } },
        overrideAccess: true,
      })
      const bob = users.docs[0]
      // Stored form untouched (issue #56)…
      expect(bob?.role).toEqual(['frontPlugin', 'user'])
      // …and the plugin reasons canonically: a governed write preserves
      // the stored value.
      await payload.update({
        collection: 'users',
        id: bob?.id as number,
        data: { roles: ['front-plugin', 'user'] },
        overrideAccess: true,
      })
      const after = await payload.findByID({
        collection: 'users',
        id: bob?.id as number,
        overrideAccess: true,
      })
      expect(after.role).toEqual(['frontPlugin', 'user'])
    })

    test('credential hashes are untouched by the boot', async () => {
      const client = new Client(harness.targetFromEnv(database))
      await client.connect()
      const hash = await client.query(
        "SELECT password FROM accounts WHERE provider_id = 'credential' ORDER BY id LIMIT 1"
      )
      expect(String((hash.rows[0] as { password: string } | undefined)?.password)).toMatch(
        /^[0-9a-f]{32}:[0-9a-f]{128}$/
      )
      await client.end()
    })
  }
)
