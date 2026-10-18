/**
 * Issue #50 acceptance, against the real payload-auth dump: the
 * importer is runnable, reversible, and honest — dry-run by default,
 * `--apply` writes a manifest and never touches the source tables,
 * `verify` checks both sides, `rollback` undoes exactly the manifest,
 * `finalize` marks the point of no return, and an old password signs
 * in after the copy.
 */
import { apiKey as apiKeyPlugin } from '@better-auth/api-key'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { nextCookies } from 'better-auth/next-js'
import { jwt, magicLink, organization } from 'better-auth/plugins'
import { authLink } from '@payload-auth-link/plugin'
import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { fileURLToPath } from 'node:url'

// Runtime-computed specifier: the typecheck project never reaches into
// fixtures/.
const harnessPath = fileURLToPath(
  new URL('../../../../fixtures/payload-auth-app/test/harness.ts', import.meta.url)
)
type Harness = {
  dropDatabase: (database: string) => Promise<void>
  expectedCounts: Readonly<Record<string, number>>
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
const fixtureConfigPath = new URL(
  '../../../../fixtures/payload-auth-app/payload.config.ts',
  import.meta.url
).pathname
import {
  finalizeManifest,
  readManifest,
  rollbackImport,
  verifyImport,
  writeManifest,
  defaultManifestPath,
} from '../importer/lifecycle.js'
import { runFromPayloadAuth } from '../importer/run-import.js'
import { findOrphans } from '../importer/source.js'
import { introspectDatabase } from '../doctor/database.js'
import type { Client } from 'pg'

const PASSWORD = 'FixturePassw0rd!'
const ORIGIN = 'http://localhost:3100'

const adoptSchemaSql = readFileSync(
  new URL('../../../../fixtures/payload-auth-app/test/adopt-schema.sql', import.meta.url),
  'utf8'
)
// The ba-* target tables, generated from the catalog of a scratch
// payload boot (see the file header). Push stays OFF for the same
// reason as adopt mode: drizzle's rename heuristics prompt on the
// payload-auth layout.
const targetSchemaSql = readFileSync(
  new URL('../../../../fixtures/payload-auth-app/test/import-target-schema.sql', import.meta.url),
  'utf8'
)

// The transitional app: the source layout stays (loose, inert), the
// engine's ba-* collections are the target, and the plugin rides the
// host users collection with the adopted role field.
const hostCollections: CollectionConfig[] = [
  {
    slug: 'users',
    auth: true,
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
      { name: 'role', type: 'text' },
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
      { name: 'status', type: 'text', defaultValue: 'pending' },
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
    const probe = harness.fixtureClient('postgres')
    await probe.connect()
    await probe.end()
    return true
  } catch {
    return false
  }
})()

describe.skipIf(!canReachPostgres)(
  'the importer refuses configs without target collections (#75)',
  () => {
    test('an untouched payload-auth config fails fast with the fix in the message — no boot, no hang', async () => {
      // The payload-auth app's own config declares NO ba-* collections:
      // exactly the state #75 hung on. The pre-flight must refuse BEFORE
      // Payload boots (no pool, no silent park).
      const startedAt = Date.now()
      const outcome = runFromPayloadAuth({
        configPath: fixtureConfigPath,
        databaseUrl: process.env.FIXTURE_DATABASE_URL ?? '',
        apply: false,
        sessions: 'carry',
      })
      await expect(outcome).rejects.toThrow(/target collections/)
      // Fast: the failure happens at the config-module read, not after a
      // database boot. (The old path parked forever; CI budgets seconds.)
      expect(Date.now() - startedAt).toBeLessThan(30_000)
    })
  }
)

/** Never reached: narrows a nullable manifest read inside an assertion. */
function unsignedNever(): never {
  throw new Error('the manifest file is missing')
}

describe.skipIf(!canReachPostgres)(
  'from-payload-auth: runnable, reversible importer (issue #50)',
  () => {
    let database: string
    let payload: Payload
    let latePayload: Payload | undefined
    let manifestPath: string
    let connectionString: string

    const engine = createBetterAuthEngine({
      getPayload: () => {
        if (latePayload === undefined) {
          throw new Error('Payload not ready')
        }
        return Promise.resolve(latePayload)
      },
      autoDeclare: true,
      options: {
        baseURL: ORIGIN,
        secret: 'import-secret-import-secret-import!',
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
      database = await harness.loadFixtureDump('pal_import')
      const target = harness.targetFromEnv(database)
      connectionString = `postgres://${target.user}:${target.password}@${target.host}:${target.port}/${database}`
      const schema = harness.fixtureClient(database)
      await schema.connect()
      await schema.query(adoptSchemaSql)
      await schema.query(targetSchemaSql)
      await schema.end()

      const config = await buildConfig({
        secret: 'import-secret-import-secret-import!',
        serverURL: ORIGIN,
        telemetry: false,
        logger: { options: { level: 'silent' } },
        admin: { user: 'users' },
        db: postgresAdapter({ push: false, pool: { connectionString } }),
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
      manifestPath = join(tmpdir(), `pal-import-${Date.now()}.json`)
    }, 240_000)

    afterAll(async () => {
      // Release Payload's pool before the database goes away, or the
      // forced termination surfaces as unhandled pg errors.
      await payload.db.destroy?.()
      await harness.dropDatabase(database)
    })

    async function sourceCounts(): Promise<Record<string, number>> {
      const client = harness.fixtureClient(database)
      await client.connect()
      const counts: Record<string, number> = {}
      for (const table of Object.keys(harness.expectedCounts)) {
        const counted = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
        counts[table] = (counted.rows[0] as { n: number } | undefined)?.n ?? -1
      }
      await client.end()
      return counts
    }

    /**
     * Strict verify counts THE IMPORT (#68) — a live sign-in creates a
     * real ba-session, and that is app traffic, not the copy. Tests
     * that sign in drop their live session afterwards so the count
     * checks keep measuring the import.
     */
    async function deleteLiveSessions(): Promise<void> {
      const client = harness.fixtureClient(database)
      await client.connect()
      const source = await client.query('SELECT token FROM sessions')
      await client.end()
      const carried = new Set(source.rows.map((row) => String((row as { token: unknown }).token)))
      const sessions = await payload.find({
        collection: 'ba-sessions',
        depth: 0,
        pagination: false,
        overrideAccess: true,
      })
      for (const doc of sessions.docs) {
        if (!carried.has(String((doc as unknown as Record<string, unknown>).token))) {
          await payload.delete({ collection: 'ba-sessions', id: doc.id, overrideAccess: true })
        }
      }
    }

    test('dry run is the default: nothing is written', async () => {
      const before = await sourceCounts()
      const outcome = await runFromPayloadAuth({
        configPath: 'unused',
        databaseUrl: connectionString,
        apply: false,
        sessions: 'carry',
        manifestPath,
        loadPayload: () => Promise.resolve(payload),
      })
      expect(outcome.exitCode).toBe(0)
      const after = await sourceCounts()
      // The dry run writes nothing anywhere.
      for (const table of Object.keys(before)) {
        expect(after[table], table).toBe(before[table])
      }
      const baUsers = await payload.count({ collection: 'ba-users', overrideAccess: true })
      expect(baUsers.totalDocs).toBe(0)
      expect(outcome.plan.unmappable).toEqual([])
      expect(outcome.unverified).toEqual(['bob@example.com', 'dave@example.com'])
    })

    test('--apply copies every row and records the manifest; hashes carry verbatim', async () => {
      const outcome = await runFromPayloadAuth({
        configPath: 'unused',
        databaseUrl: connectionString,
        apply: true,
        sessions: 'carry',
        manifestPath,
        loadPayload: () => Promise.resolve(payload),
        // The proof is opt-in (GHSA-mjvh follow-up); this run opts in.
        grantLinkableFromVerified: true,
      })
      expect(outcome.exitCode).toBe(0)
      expect(outcome.result?.created ?? 0).toBeGreaterThan(10)
      // Counts: one ba-user + accounts + carried sessions + verifications
      // + api keys + jwks + orgs/members/invitations.
      for (const [slug, expected] of [
        ['ba-users', harness.expectedCounts.users],
        ['ba-accounts', harness.expectedCounts.accounts],
        ['ba-sessions', harness.expectedCounts.sessions],
        ['ba-verifications', harness.expectedCounts.verifications],
        ['ba-apikey', harness.expectedCounts.api_keys],
        ['ba-jwks', harness.expectedCounts.jwks],
        ['ba-organization', harness.expectedCounts.organizations],
        ['ba-member', harness.expectedCounts.members],
        ['ba-invitation', harness.expectedCounts.invitations],
      ] as const) {
        const counted = await payload.count({ collection: slug, overrideAccess: true })
        expect(counted.totalDocs, slug).toBe(expected)
      }
      const manifest = readManifest(manifestPath)
      expect(manifest?.created.length).toBeGreaterThan(10)
      expect(manifest?.options.sessions).toBe('carry')
      expect(manifest?.finalized).toBe(false)
      // Password hashes copied verbatim.
      const client = harness.fixtureClient(database)
      await client.connect()
      const sourceHash = await client.query(
        "SELECT password FROM accounts WHERE provider_id = 'credential' ORDER BY id LIMIT 1"
      )
      await client.end()
      const accounts = await payload.find({
        collection: 'ba-accounts',
        where: { providerId: { equals: 'credential' } },
        depth: 0,
        overrideAccess: true,
      })
      const hashes = new Set(accounts.docs.map((doc) => String(doc.password)))
      expect(hashes.has(String((sourceHash.rows[0] as { password: string }).password))).toBe(true)
      // With the opt-in, the linkable proof comes from VERIFIED emails only.
      const users = await payload.find({ collection: 'ba-users', depth: 0, overrideAccess: true })
      const bob = users.docs.find((doc) => doc.email === 'bob@example.com')
      const alice = users.docs.find((doc) => doc.email === 'alice@example.com')
      expect(alice?.emailVerified).toBe(true)
      expect(bob?.emailVerified).toBe(false)
      const hostDocs = await payload.find({
        collection: 'users',
        where: { email: { in: ['alice@example.com', 'bob@example.com'] } },
        depth: 0,
        overrideAccess: true,
      })
      for (const doc of hostDocs.docs) {
        if (doc.email === 'alice@example.com') {
          expect(doc.linkable).toBe(true)
          expect(doc.linkableEmail).toBe('alice@example.com')
        } else {
          expect(doc.linkable).toBe(false)
        }
      }
    })

    test('verify checks both sides and passes', async () => {
      const result = await verifyImport({
        payload,
        sourceConnectionString: connectionString,
      })
      expect(result.issues).toEqual([])
      expect(result.ok).toBe(true)
      // The roles check reads the CONFIGURED roles field (`role` here),
      // so it runs instead of being skipped (#110).
      const roles = result.checks.find((check) =>
        check.name.startsWith('source roles carried onto the host docs')
      )
      expect(roles).toEqual({ name: 'source roles carried onto the host docs', passed: true })
    })

    test('rollback refuses an edited manifest before touching anything (GHSA-p76j-5qwx-rpwx)', async () => {
      const manifest = readManifest(manifestPath)
      if (manifest === null) {
        throw new Error('unreachable')
      }
      expect(manifest.version).toBe(4)
      const host = await payload.find({ collection: 'users', depth: 0, overrideAccess: true })
      const victim = host.docs[0]
      if (victim === undefined) {
        throw new Error('fixture has no users')
      }
      const baBefore = await payload.count({ collection: 'ba-users', overrideAccess: true })
      // An extra delete target, and a plaintext roles entry.
      const edited = {
        ...manifest,
        created: [{ collection: 'users', id: victim.id, sourceKey: 'edited' }, ...manifest.created],
        fieldWrites: [
          ...manifest.fieldWrites,
          { collection: 'users', id: victim.id, field: 'roles', before: '["admin"]' },
        ],
      }
      await expect(rollbackImport({ payload, manifest: edited })).rejects.toThrow(/integrity check/)
      // A stripped MAC is no way around it either.
      const unsigned = {
        ...edited,
        mac: undefined,
        version: 2 as const,
        databaseId: undefined,
        runId: undefined,
      }
      await expect(rollbackImport({ payload, manifest: unsigned })).rejects.toThrow(
        /allow-unsigned-manifest/
      )
      const still = await payload.findByID({
        collection: 'users',
        id: victim.id,
        depth: 0,
        overrideAccess: true,
      })
      expect(still.id).toBe(victim.id)
      expect(
        (await payload.count({ collection: 'ba-users', overrideAccess: true })).totalDocs
      ).toBe(baBefore.totalDocs)
    })

    test('an unsigned manifest cannot delete a host row, even with every opt-in', async () => {
      const manifest = readManifest(manifestPath)
      if (manifest === null) {
        throw new Error('unreachable')
      }
      // The host app's own `jwks` collection (payload-auth's table) —
      // NOT the engine's ba-jwks the importer writes.
      const hostJwks = await payload.find({ collection: 'jwks', depth: 0, overrideAccess: true })
      const victim = hostJwks.docs[0]
      if (victim === undefined) {
        throw new Error('fixture has no jwks row')
      }
      const baBefore = (await payload.count({ collection: 'ba-users', overrideAccess: true }))
        .totalDocs
      const downgraded = {
        ...manifest,
        version: 2 as const,
        mac: undefined,
        databaseId: undefined,
        runId: undefined,
        created: [...manifest.created, { collection: 'jwks', id: victim.id, sourceKey: 'jwks:1' }],
      }
      // This database ran 0.8: no unsigned manifest is accepted at all
      // (GHSA-xw9m-ph95-84rx).
      await expect(
        rollbackImport({
          payload,
          manifest: downgraded,
          allowUnsignedManifest: true,
          allowUnsignedDeletes: true,
        })
      ).rejects.toThrow(/has run migrate 0\.8\.0 or later/)
      // Where unsigned manifests are still accepted (a database that
      // never ran 0.8 — simulated by hiding its id), the guards below
      // hold on their own.
      const idKey = 'payload-auth-link/migrate/database-id'
      const idRecord = await payload.kv.get(idKey)
      if (idRecord === null) {
        throw new Error('the apply recorded no database id')
      }
      await payload.kv.delete(idKey)
      try {
        await expect(
          rollbackImport({
            payload,
            manifest: downgraded,
            allowUnsignedManifest: true,
            allowUnsignedDeletes: true,
          })
        ).rejects.toThrow(/outside the import's target collections/)
        // --allow-unsigned-manifest alone never deletes, even in-scope rows.
        await expect(
          rollbackImport({
            payload,
            manifest: {
              ...manifest,
              version: 2 as const,
              mac: undefined,
              databaseId: undefined,
              runId: undefined,
            },
            allowUnsignedManifest: true,
          })
        ).rejects.toThrow(/--allow-unsigned-deletes/)
        // With every opt-in, the run-bound values copied out of the
        // signed manifest still open for no other manifest.
        await expect(
          rollbackImport({
            payload,
            manifest: {
              ...manifest,
              version: 2 as const,
              mac: undefined,
              databaseId: undefined,
              runId: undefined,
              created: [],
            },
            allowUnsignedManifest: true,
            allowUnsignedDeletes: true,
          })
        ).rejects.toThrow(/manifest names none/)
      } finally {
        await payload.kv.set(idKey, idRecord)
      }
      const still = await payload.findByID({
        collection: 'jwks',
        id: victim.id,
        depth: 0,
        overrideAccess: true,
      })
      expect(still.id).toBe(victim.id)
      expect(
        (await payload.count({ collection: 'ba-users', overrideAccess: true })).totalDocs
      ).toBe(baBefore)
    })

    test('rollback undoes exactly the manifest; the source is unchanged', async () => {
      const before = await sourceCounts()
      const manifest = readManifest(manifestPath)
      expect(manifest).not.toBeNull()
      if (manifest === null) {
        throw new Error('unreachable')
      }
      const undone = await rollbackImport({ payload, manifest })
      expect(undone.deleted).toBe(manifest.created.length)
      // Every ba-* collection is empty again, and the host users' field
      // writes are restored.
      for (const slug of [
        'ba-users',
        'ba-accounts',
        'ba-sessions',
        'ba-verifications',
        'ba-apikey',
        'ba-jwks',
        'ba-organization',
        'ba-member',
        'ba-invitation',
      ]) {
        const counted = await payload.count({ collection: slug, overrideAccess: true })
        expect(counted.totalDocs, slug).toBe(0)
      }
      const hostDocs = await payload.find({
        collection: 'users',
        depth: 0,
        overrideAccess: true,
      })
      for (const doc of hostDocs.docs) {
        expect(doc.linkable, String(doc.email)).toBe(false)
        expect(doc.identities).toEqual([])
      }
      // The source tables were never modified.
      const after = await sourceCounts()
      for (const table of Object.keys(before)) {
        expect(after[table], table).toBe(before[table])
      }
    })

    test('re-apply and finalize close the run', async () => {
      // The file still holds the rolled-back run's manifest (the
      // rollback above ran without a path to reset): the database
      // records that run as rolled back, so the re-apply starts FRESH.
      const stale = readManifest(manifestPath)
      await expect(rollbackImport({ payload, manifest: stale ?? unsignedNever() })).rejects.toThrow(
        /stale copy/
      )
      const outcome = await runFromPayloadAuth({
        configPath: 'unused',
        databaseUrl: connectionString,
        apply: true,
        sessions: 'carry',
        manifestPath,
        loadPayload: () => Promise.resolve(payload),
      })
      expect(outcome.exitCode).toBe(0)
      const manifest = readManifest(manifestPath)
      expect(manifest?.finalized).toBe(false)
      expect(manifest?.runId).toBeDefined()
      expect(manifest?.runId).not.toBe(stale?.runId)
      expect(manifest?.databaseId).toBe(stale?.databaseId)
      // Without --grant-linkable-from-verified no proof is granted
      // (GHSA-mjvh follow-up): alice is verified on the source, yet her
      // document gets the identity only.
      const alice = await payload.find({
        collection: 'users',
        where: { email: { equals: 'alice@example.com' } },
        depth: 0,
        overrideAccess: true,
      })
      expect(alice.docs[0]?.linkable).toBe(false)
      expect(alice.docs[0]?.identities).toHaveLength(1)
      if (manifest === null) {
        throw new Error('unreachable')
      }
      const finalized = await finalizeManifest({ payload, manifest, path: manifestPath })
      expect(finalized.finalized).toBe(true)
      expect(finalized.mac).toMatch(/^v2\./)
      expect(readManifest(manifestPath)?.finalized).toBe(true)
      // Rollback is no longer possible after finalize.
      await expect(rollbackImport({ payload, manifest: finalized })).rejects.toThrow(
        /no longer possible/
      )
    })

    test('flipping finalized back does not reopen rollback: the MAC covers it, the database remembers', async () => {
      const finalized = readManifest(manifestPath)
      if (finalized === null) {
        throw new Error('unreachable')
      }
      const baBefore = (await payload.count({ collection: 'ba-users', overrideAccess: true }))
        .totalDocs
      // The flag edited in place: the signature covers it now.
      await expect(
        rollbackImport({ payload, manifest: { ...finalized, finalized: false } })
      ).rejects.toThrow(/integrity check/)
      // An unfinalized copy the app DID sign (a backup from before
      // finalize) still verifies — the database marker refuses it.
      const { signManifest } = await import('../importer/manifest-mac.js')
      const preFinalize = signManifest(payload.secret, {
        ...finalized,
        finalized: false,
        finalizedAt: undefined,
      })
      await expect(rollbackImport({ payload, manifest: preFinalize })).rejects.toThrow(
        /database records a finalized migration/
      )
      // Downgraded to an unsigned version with every opt-in: still refused.
      await expect(
        rollbackImport({
          payload,
          manifest: {
            ...preFinalize,
            version: 2,
            mac: undefined,
            databaseId: undefined,
            runId: undefined,
            createdAt: 'forged',
          },
          allowUnsignedManifest: true,
          allowUnsignedDeletes: true,
        })
      ).rejects.toThrow(/finalized/)
      expect(
        (await payload.count({ collection: 'ba-users', overrideAccess: true })).totalDocs
      ).toBe(baBefore)
    })

    test('an old password signs in on the new stack', async () => {
      const response = await engine.auth.handler(
        new Request(`${ORIGIN}/api/auth/sign-in/email`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: ORIGIN },
          body: JSON.stringify({ email: 'carol@example.com', password: PASSWORD }),
        })
      )
      expect(response.status).toBe(200)
      // The strict count checks measure the import, not live traffic.
      await deleteLiveSessions()
    })

    test('verify remains green after the re-apply', async () => {
      const result = await verifyImport({ payload, sourceConnectionString: connectionString })
      expect(result.ok, JSON.stringify(result.issues)).toBe(true)
    })

    test('manifest bookkeeping round-trips through the helpers', () => {
      const path = join(tmpdir(), `pal-import-${Date.now()}-x.json`)
      const manifest = {
        version: 1 as const,
        createdAt: new Date().toISOString(),
        sourceDatabase: 'postgres://***@db',
        options: { sessions: 'carry' as const },
        created: [],
        fieldWrites: [],
        finalized: false,
        sourceCounts: {},
        totals: {},
      }
      writeManifest(manifest, path)
      expect(readManifest(path)?.version).toBe(1)
      // defaultManifestPath is the documented location
      expect(defaultManifestPath).toBe('payload-auth-link-migration.json')
    })

    test('imported users carry exactly one better-auth identity resolving to their ba-users id (#69)', async () => {
      const baUsers = await payload.find({
        collection: 'ba-users',
        depth: 0,
        pagination: false,
        overrideAccess: true,
      })
      expect(baUsers.totalDocs).toBe(harness.expectedCounts.users)
      for (const doc of baUsers.docs) {
        const record = doc as unknown as Record<string, unknown>
        const baId = String(record['baId'])
        // The host document the source user id IS (hostId = source id).
        const host = await payload.findByID({
          collection: 'users',
          id: Number(baId),
          depth: 0,
          overrideAccess: true,
        })
        const identities = (host as unknown as Record<string, unknown>)['identities'] as
          | { providerId: string; providerUserId: string; email: string; linkedAt: string }[]
          | undefined
        expect(Array.isArray(identities), baId).toBe(true)
        expect(identities, baId).toHaveLength(1)
        const only = identities?.[0]
        expect(only?.providerId, baId).toBe('better-auth')
        // The engine serves BA's user.id from the ba-users baId column,
        // so this is exactly what findByProviderIdentity queries back.
        expect(only?.providerUserId, baId).toBe(baId)
        expect(only?.email, baId).toBe(String(record['email']))
      }
    })

    test('a user who verifies after the import resolves to the ORIGINAL document (#69)', async () => {
      const bobDocs = await payload.find({
        collection: 'ba-users',
        where: { email: { equals: 'bob@example.com' } },
        depth: 0,
        overrideAccess: true,
      })
      const bob = bobDocs.docs[0]
      if (bob === undefined) {
        throw new Error('bob missing from ba-users')
      }
      const baId = String((bob as unknown as Record<string, unknown>)['baId'])
      // Simulate the email verifying AFTER the import window (bob came
      // in unverified; the import never granted linkable).
      await payload.update({
        collection: 'ba-users',
        id: bob.id,
        data: { emailVerified: true },
        overrideAccess: true,
      })
      // His old password still signs in on the new stack.
      const response = await engine.auth.handler(
        new Request(`${ORIGIN}/api/auth/sign-in/email`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: ORIGIN },
          body: JSON.stringify({ email: 'bob@example.com', password: PASSWORD }),
        })
      )
      expect(response.status).toBe(200)
      // The test tree has no external provider to round-trip a session
      // through, so the data-intact half is asserted at the lookup the
      // session resolver performs: the imported identity row answers
      // EXACTLY the query findByProviderIdentity issues
      // ({ 'identities.providerId': 'better-auth',
      //    'identities.providerUserId': <BA user id> }) and resolves to
      // bob's ORIGINAL host document id (hostId = source user id).
      const resolved = await payload.find({
        collection: 'users',
        where: {
          and: [
            { 'identities.providerId': { equals: 'better-auth' } },
            { 'identities.providerUserId': { equals: baId } },
          ],
        },
        depth: 0,
        overrideAccess: true,
      })
      expect(resolved.totalDocs).toBe(1)
      expect(Number(resolved.docs[0]?.id)).toBe(Number(baId))
      // The sign-in above is live traffic, not the import.
      await deleteLiveSessions()
    })

    test('an unknown --source-map model is a usage error, not a silent skip (#68)', async () => {
      await expect(
        runFromPayloadAuth({
          configPath: 'unused',
          databaseUrl: connectionString,
          apply: false,
          sessions: 'carry',
          manifestPath,
          // Typo on purpose: 'acounts' is not a source model.
          sourceMapJson: '{"acounts":"user_accounts"}',
          loadPayload: () => Promise.resolve(payload),
        })
      ).rejects.toThrow(/unknown model/)
    })

    test('a renamed source layout blocks the dry run until --source-map maps it (#68)', async () => {
      const alt = await harness.loadFixtureDump('pal_import_alt')
      const altTarget = harness.targetFromEnv(alt)
      const altUrl = `postgres://${altTarget.user}:${altTarget.password}@${altTarget.host}:${altTarget.port}/${alt}`
      const renamer = harness.fixtureClient(alt)
      await renamer.connect()
      await renamer.query('ALTER TABLE accounts RENAME TO user_accounts')
      await renamer.query('ALTER TABLE sessions RENAME TO user_sessions')
      await renamer.end()
      try {
        const loadPayload = () => Promise.resolve(payload)
        const blocked = await runFromPayloadAuth({
          configPath: 'unused',
          databaseUrl: altUrl,
          apply: false,
          sessions: 'carry',
          manifestPath,
          loadPayload,
        })
        expect(blocked.exitCode).toBe(1)
        const reasons = blocked.plan.unmappable.map((row) => row.reason).join(' ')
        expect(reasons).toContain("'accounts'")
        expect(reasons).toContain("'sessions'")
        expect(reasons).toContain('--source-map')
        expect(blocked.result).toBeUndefined()

        // With the map, the SAME layout plans cleanly.
        const mapped = await runFromPayloadAuth({
          configPath: 'unused',
          databaseUrl: altUrl,
          apply: false,
          sessions: 'carry',
          manifestPath,
          sourceMapJson: '{"accounts":"user_accounts","sessions":"user_sessions"}',
          loadPayload,
        })
        expect(mapped.exitCode).toBe(0)
        expect(mapped.plan.unmappable).toEqual([])
        expect(mapped.unverified).toEqual(['bob@example.com', 'dave@example.com'])
        // The dry run wrote nothing.
        const baUsers = await payload.count({ collection: 'ba-users', overrideAccess: true })
        expect(baUsers.totalDocs).toBe(harness.expectedCounts.users)

        // The orphan sweep reports the checks it could not run instead
        // of passing silently.
        const scanClient = harness.fixtureClient(alt)
        await scanClient.connect()
        const scan = await findOrphans(scanClient)
        await scanClient.end()
        const skipped = scan.skipped.join(' ')
        expect(skipped).toContain("'accounts'")
        expect(skipped).toContain("'sessions'")
        expect(skipped).not.toContain('apikey')
      } finally {
        await harness.dropDatabase(alt)
      }
    })

    test('the api-key orphan check runs on the reference_id layout and finds an orphan (#68)', async () => {
      const client = harness.fixtureClient(database)
      await client.connect()
      const nextId = await client.query('SELECT (max(id) + 1)::int AS id FROM api_keys')
      const id = (nextId.rows[0] as { id: number }).id
      await client.query(
        'INSERT INTO api_keys (id, config_id, reference_id, key) VALUES ($1, $2, $3, $4)',
        [id, 'default', 99999, 'orphan-key-value']
      )
      try {
        // The importer's sweep probes the owner column by layout:
        // reference_id (current), user_id (1.6-era) — never silent.
        const scan = await findOrphans(client)
        const orphan = scan.orphans.find((row) => row.model === 'apikey')
        expect(orphan?.reason).toContain('reference_id')
        expect(scan.skipped.join(' ')).not.toContain('apikey')
        // The doctor's database section reports the same orphan.
        const found = await introspectDatabase(connectionString)
        expect(found.orphans.map((entry) => entry.kind)).toContain('api-keys-without-user')
        // The fixture layout is complete: nothing missing, no skips.
        expect(found.missingTables).toEqual([])
        expect(found.skippedChecks).toEqual([])
      } finally {
        await client.query('DELETE FROM api_keys WHERE id = $1', [id])
        await client.end()
      }
    })

    test('verify is strict: an extra target row fails where >= once passed (#68)', async () => {
      const stray = await payload.create({
        collection: 'ba-users',
        data: { baId: '999999', email: 'stray@example.com', name: 'Stray', emailVerified: false },
        overrideAccess: true,
      })
      try {
        const result = await verifyImport({ payload, sourceConnectionString: connectionString })
        expect(result.ok).toBe(false)
        const detail = result.issues.map((issue) => issue.detail).join(' ')
        expect(detail).toContain('exactly 4 users')
        expect(detail).toContain('ba-users')
      } finally {
        await payload.delete({ collection: 'ba-users', id: stray.id, overrideAccess: true })
      }
      const green = await verifyImport({ payload, sourceConnectionString: connectionString })
      expect(green.ok, JSON.stringify(green.issues)).toBe(true)
    })

    test('verify is strict: zero source rows no longer skip the count (#68)', async () => {
      const client = harness.fixtureClient(database)
      await client.connect()
      const saved = await client.query(
        'SELECT id, identifier, value, expires_at FROM verifications ORDER BY id LIMIT 1'
      )
      const row = saved.rows[0] as {
        id: number
        identifier: string
        value: string
        expires_at: Date
      }
      await client.query('DELETE FROM verifications')
      try {
        const failed = await verifyImport({ payload, sourceConnectionString: connectionString })
        expect(failed.ok).toBe(false)
        const detail = failed.issues.map((issue) => issue.detail).join(' ')
        expect(detail).toContain('exactly 0 verifications')
      } finally {
        await client.query(
          'INSERT INTO verifications (id, identifier, value, expires_at) VALUES ($1, $2, $3, $4)',
          [row.id, row.identifier, row.value, row.expires_at]
        )
        await client.end()
      }
      const green = await verifyImport({ payload, sourceConnectionString: connectionString })
      expect(green.ok, JSON.stringify(green.issues)).toBe(true)
    })

    test('verify is strict: a missing credential account fails and is restored exactly (#68)', async () => {
      const accounts = await payload.find({
        collection: 'ba-accounts',
        where: { providerId: { equals: 'credential' } },
        depth: 0,
        pagination: false,
        overrideAccess: true,
      })
      const victim = accounts.docs[0]
      if (victim === undefined) {
        throw new Error('no credential account to test with')
      }
      const record = victim as unknown as Record<string, unknown>
      await payload.delete({ collection: 'ba-accounts', id: victim.id, overrideAccess: true })
      try {
        const result = await verifyImport({ payload, sourceConnectionString: connectionString })
        expect(result.ok).toBe(false)
        const detail = result.issues.map((issue) => issue.detail).join(' ')
        expect(detail).toContain('exactly 6 accounts')
      } finally {
        // Recreate with the same baId — exactly what a resumed import
        // would do (a fresh document id, the same deterministic key).
        await payload.create({
          collection: 'ba-accounts',
          data: {
            baId: String(record['baId']),
            accountId: String(record['accountId']),
            providerId: String(record['providerId']),
            userId: String(record['userId']),
            ...(typeof record['password'] === 'string' ? { password: record['password'] } : {}),
          },
          overrideAccess: true,
        })
      }
      const green = await verifyImport({ payload, sourceConnectionString: connectionString })
      expect(green.ok, JSON.stringify(green.issues)).toBe(true)
    })

    test('a null-mapped model is skipped by config, never probed or counted (#68)', async () => {
      const result = await verifyImport({
        payload,
        sourceConnectionString: connectionString,
        sourceTables: { verifications: null },
      })
      expect(result.ok, JSON.stringify(result.issues)).toBe(true)
      const names = result.checks.map((check) => check.name).join(' ')
      expect(names).toContain('null-mapped')
      expect(names).toContain('verifications')
    })
  }
)
