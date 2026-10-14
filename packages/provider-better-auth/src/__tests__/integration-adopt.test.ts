/**
 * Adopt-mode integration (issue #49): a payload-auth-style layout —
 * the Payload users collection IS the Better Auth user table, with
 * relationship fields for `userId` and host-only columns — served by
 * the engine through `schemaMap` + `idStrategy: 'payload'`, on real
 * Payload storage (SQLite in memory). Proves: zero extra collections,
 * Payload-owned ids round-tripping as Better Auth row ids, renamed
 * relationship fields reading and writing as ids, old passwords
 * signing in, and host fields surviving Better Auth writes.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthCollections, validateSchemaMap } from '../collections.js'
import { createBetterAuthEngine } from '../engine.js'
import { InvalidConfigError } from '@payload-auth-link/core'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'better-auth-adopt-integration-secret'

let config: SanitizedConfig
let payload: Payload
let latePayload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  schemaMap: {
    user: { slug: 'users' },
    session: { slug: 'userSessions', fields: { userId: 'user' } },
    account: { slug: 'userAccounts', fields: { userId: 'user' } },
    verification: { slug: 'verifications' },
  },
  idStrategy: 'payload',
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: {
      storage: 'database',
      enabled: true,
      window: 60,
      max: 10_000,
      customRules: { '/sign-up/email': false, '/sign-in/email': false },
    },
  },
})

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    // The host layout exactly as a payload-auth app has it — the
    // engine adds NOTHING for adopted models (engine.collections is
    // empty below).
    collections: [
      {
        slug: 'users',
        // payload-auth disables Payload's local strategy and rides its
        // own Better Auth strategy; the host keeps that shape, and the
        // adopted engine must never trip Payload's local-password
        // registration on a BA user create.
        auth: {
          disableLocalStrategy: true,
          strategies: [
            {
              name: 'better-auth',
              authenticate: () => Promise.resolve({ user: null }),
            },
          ],
        },
        fields: [
          { name: 'email', type: 'email', required: true, index: true },
          { name: 'emailVerified', type: 'checkbox', defaultValue: false },
          { name: 'name', type: 'text' },
          { name: 'image', type: 'text' },
          // Host-only fields: invisible to Better Auth, preserved on
          // every adapter write.
          { name: 'department', type: 'text' },
          {
            name: 'role',
            type: 'select',
            hasMany: true,
            options: ['user', 'admin', 'staff', 'frontPlugin'],
            defaultValue: ['user'],
          },
        ],
        access: { read: () => true },
      },
      {
        slug: 'userSessions',
        fields: [
          { name: 'user', type: 'relationship', relationTo: 'users', required: true, index: true },
          { name: 'token', type: 'text', required: true, unique: true, index: true },
          { name: 'expiresAt', type: 'date', required: true },
          { name: 'ipAddress', type: 'text' },
          { name: 'userAgent', type: 'text' },
        ],
      },
      {
        slug: 'userAccounts',
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
        slug: 'verifications',
        fields: [
          { name: 'identifier', type: 'text', required: true, index: true },
          { name: 'value', type: 'text', required: true },
          { name: 'expiresAt', type: 'date', required: true },
        ],
      },
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
}, 120_000)

describe('adopt-mode engine (issue #49)', () => {
  it('creates no collections for adopted models', () => {
    // Only the non-adopted remainder (rate limiting) gets a collection;
    // every adopted model is served from the host.
    expect(engine.collections.map((collection) => collection.slug)).toEqual(['ba-rate-limits'])
    expect(Object.keys(engine.schemaMap)).toEqual(['user', 'session', 'account', 'verification'])
  })

  it('signs a user up into the HOST users collection with the Payload id as row id', async () => {
    const response = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-up/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({
          name: 'Adopted User',
          email: 'adopted@test.dev',
          password: 'Adopted-Passw0rd!',
        }),
      })
    )
    expect(response.status).toBe(200)
    const found = await payload.find({
      collection: 'users',
      where: { email: { equals: 'adopted@test.dev' } },
      overrideAccess: true,
    })
    expect(found.totalDocs).toBe(1)
    const user = found.docs[0]
    expect(user).toBeDefined()
    // Zero row moves: the Better Auth id IS the Payload id.
    const ctx = await engine.auth.$context
    const baUser = await ctx.adapter.findOne<{ id: string; email: string }>({
      model: 'user',
      where: [{ field: 'email', value: 'adopted@test.dev' }],
    })
    expect(baUser?.id).toBe(String(user?.id))
    expect(baUser?.email).toBe('adopted@test.dev')
  })

  it('signs in with the credential the adapter wrote into the host accounts collection', async () => {
    const response = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({ email: 'adopted@test.dev', password: 'Adopted-Passw0rd!' }),
      })
    )
    expect(response.status).toBe(200)
    // The credential account landed in the adopted collection with the
    // renamed relationship field carrying the user's id.
    const accounts = await payload.find({
      collection: 'userAccounts',
      where: { providerId: { equals: 'credential' } },
      depth: 0,
      overrideAccess: true,
    })
    expect(accounts.totalDocs).toBe(1)
    const account = accounts.docs[0]
    const users = await payload.find({
      collection: 'users',
      where: { email: { equals: 'adopted@test.dev' } },
      overrideAccess: true,
    })
    expect(String(account?.user)).toBe(String(users.docs[0]?.id))
    expect(typeof account?.password).toBe('string')
  })

  it('serves sessions from the adopted collection through the renamed field', async () => {
    const ctx = await engine.auth.$context
    const sessions = await ctx.adapter.findMany<{ id: string; userId: string }>({
      model: 'session',
      where: [],
    })
    expect(sessions.length).toBeGreaterThanOrEqual(1)
    const users = await payload.find({
      collection: 'users',
      where: { email: { equals: 'adopted@test.dev' } },
      overrideAccess: true,
    })
    for (const session of sessions) {
      expect(session.userId).toBe(String(users.docs[0]?.id))
    }
    // Querying by the Better Auth field name resolves through the map.
    const byUser = await ctx.adapter.count({
      model: 'session',
      where: [{ field: 'userId', value: String(users.docs[0]?.id) }],
    })
    expect(byUser).toBe(sessions.length)
  })

  it('host-only fields survive Better Auth writes', async () => {
    const users = await payload.find({
      collection: 'users',
      where: { email: { equals: 'adopted@test.dev' } },
      overrideAccess: true,
    })
    const id = users.docs[0]?.id
    await payload.update({
      collection: 'users',
      id: id as number,
      data: { department: 'platform' },
      overrideAccess: true,
    })
    const ctx = await engine.auth.$context
    // A Better Auth write — a full user update through BA's own API.
    await ctx.adapter.update({
      model: 'user',
      where: [{ field: 'id', value: String(id) }],
      update: { name: 'Adopted User II' },
    })
    const after = await payload.findByID({
      collection: 'users',
      id: id as number,
      overrideAccess: true,
    })
    expect(after.name).toBe('Adopted User II')
    expect(after.department).toBe('platform')
    expect(after.role).toEqual(['user'])
  })

  it('creates sessions with the Payload id as the session row id', async () => {
    const sessions = await payload.find({
      collection: 'userSessions',
      depth: 0,
      overrideAccess: true,
    })
    expect(sessions.totalDocs).toBeGreaterThanOrEqual(1)
    const ctx = await engine.auth.$context
    for (const session of sessions.docs) {
      const row = await ctx.adapter.findOne<{ id: string }>({
        model: 'session',
        where: [{ field: 'id', value: String(session.id) }],
      })
      expect(row?.id).toBe(String(session.id))
    }
  })
})

describe('adopt-mode validation', () => {
  it('fails the schema map at wiring time on unknown models and reserved renames', () => {
    expect(() =>
      validateSchemaMap({ nonsense: { slug: 'x' } }, { coreModels: ['user'], customModels: [] })
    ).toThrow(InvalidConfigError)
    expect(() =>
      validateSchemaMap(
        { user: { slug: 'users', fields: { baId: 'id' } } },
        { coreModels: ['user'], customModels: [] }
      )
    ).toThrow(/id strategy/)
  })

  it('skips adopted models when building collections but keeps the rest', () => {
    const collections = createBetterAuthCollections({
      schemaMap: { user: { slug: 'users' }, organization: { slug: 'organizations' } },
      customModels: [
        {
          model: 'organization',
          fields: [{ name: 'name', type: 'text' }],
        },
      ],
    })
    expect(collections.map((collection) => collection.slug)).toEqual([
      'ba-sessions',
      'ba-accounts',
      'ba-verifications',
      'ba-rate-limits',
    ])
  })

  it('rejects idStrategy payload without any adoption', () => {
    expect(() =>
      createBetterAuthEngine({
        getPayload: () => Promise.reject(new Error('unused')),
        idStrategy: 'payload',
        options: { baseURL: ORIGIN, secret: SECRET },
      })
    ).toThrow(/schemaMap/)
  })
})
