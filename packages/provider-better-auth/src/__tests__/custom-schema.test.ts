/**
 * Custom-schema integration: a real engine with `additionalFields` and
 * the organization plugin on real Payload storage (SQLite in memory).
 * Proves declared custom fields round-trip end to end, custom plugin
 * models serve full CRUD with where/date handling, and undeclared
 * extras still fail fast.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { organization } from 'better-auth/plugins'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { UnsupportedSchemaError } from '../errors.js'

const ORIGIN = 'http://custom-schema.test'
const SECRET = 'custom-schema-integration-secret!!'

let latePayload: Payload | undefined
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  // Mirrors the live Better Auth schema exactly: one `additionalFields`
  // entry, one plugin-added core field, three plugin models.
  customFields: {
    user: [{ name: 'favoriteColor', type: 'text' }],
    session: [{ name: 'activeOrganizationId', type: 'text' }],
  },
  customModels: [
    {
      model: 'organization',
      fields: [
        { name: 'name', type: 'text', required: true },
        { name: 'slug', type: 'text', required: true, unique: true },
        { name: 'logo', type: 'text' },
        { name: 'metadata', type: 'text' },
      ],
    },
    {
      model: 'member',
      fields: [
        { name: 'organizationId', type: 'text', required: true },
        { name: 'userId', type: 'text', required: true },
        { name: 'role', type: 'text', required: true },
      ],
    },
    {
      model: 'invitation',
      fields: [
        { name: 'organizationId', type: 'text', required: true },
        { name: 'email', type: 'text', required: true },
        { name: 'role', type: 'text', required: true },
        { name: 'status', type: 'text', required: true },
        { name: 'expiresAt', type: 'date', required: true },
        { name: 'inviterId', type: 'text', required: true },
      ],
    },
  ],
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    user: { additionalFields: { favoriteColor: { type: 'string', required: false } } },
    plugins: [organization()],
  },
})

let payload: Payload

beforeAll(async () => {
  const config: SanitizedConfig = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
  })
  payload = await getPayload({ config })
  latePayload = payload
  // Surface adapter/schema init failures here, not on first request.
  await engine.auth.$context
}, 120_000)

describe('custom fields on core models', () => {
  it('round-trips an additionalFields entry through signup and session read', async () => {
    const signup = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-up/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({
          name: 'Grace Hopper',
          email: 'grace@custom-schema.test',
          password: 'correct-horse-battery',
          favoriteColor: 'navy',
        }),
      })
    )
    expect(signup.status).toBe(200)
    const [user] = (
      await payload.find({
        collection: 'ba-users',
        where: { email: { equals: 'grace@custom-schema.test' } },
        overrideAccess: true,
      })
    ).docs as { favoriteColor?: unknown }[]
    expect(user?.favoriteColor).toBe('navy')

    const setCookies = signup.headers.getSetCookie()
    const session = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/get-session`, {
        headers: { cookie: setCookies.join('; '), origin: ORIGIN },
      })
    )
    expect(session.status).toBe(200)
    const body = (await session.json()) as { user?: { favoriteColor?: unknown } }
    expect(body.user?.favoriteColor).toBe('navy')
  })
})

describe('custom plugin models', () => {
  it('serves full CRUD with where clauses on custom fields', async () => {
    const ctx = await engine.auth.$context
    const org = await ctx.adapter.create<{
      id: string
      name: string
      slug: string
      logo: string | null
      metadata: string | null
    }>({
      model: 'organization',
      data: { name: 'Acme', slug: 'acme', logo: null, metadata: null },
    })
    expect(org.id).toEqual(expect.any(String))
    await ctx.adapter.create({
      model: 'member',
      data: { organizationId: org.id, userId: 'user-1', role: 'owner' },
    })
    await ctx.adapter.create({
      model: 'member',
      data: { organizationId: org.id, userId: 'user-2', role: 'member' },
    })

    const owners = await ctx.adapter.findMany<{ userId: string }>({
      model: 'member',
      where: [
        { field: 'organizationId', value: org.id },
        { field: 'role', value: 'owner' },
      ],
    })
    expect(owners).toHaveLength(1)
    expect(owners[0]?.userId).toBe('user-1')

    const renamed = await ctx.adapter.update<{ slug: string }>({
      model: 'organization',
      where: [{ field: 'id', value: org.id }],
      update: { slug: 'acme-2' },
    })
    expect(renamed?.slug).toBe('acme-2')

    const removed = await ctx.adapter.deleteMany({
      model: 'member',
      // Empty where is refused (SEC-4): bulk deletes name their rows.
      where: [{ field: 'organizationId', value: org.id }],
    })
    expect(removed).toBe(2)
    expect(await ctx.adapter.count({ model: 'member' })).toBe(0)
  })

  it('converts custom date fields both directions', async () => {
    const ctx = await engine.auth.$context
    const expires = new Date('2027-03-01T00:00:00.000Z')
    const created = await ctx.adapter.create<{
      organizationId: string
      email: string
      role: string
      status: string
      expiresAt: Date
      inviterId: string
    }>({
      model: 'invitation',
      data: {
        organizationId: 'org-1',
        email: 'invited@test.dev',
        role: 'member',
        status: 'pending',
        expiresAt: expires,
        inviterId: 'user-1',
      },
    })
    expect(created.expiresAt).toEqual(expires)
    const [row] = (await payload.find({ collection: 'ba-invitation', overrideAccess: true }))
      .docs as { expiresAt?: unknown }[]
    expect(row?.expiresAt).toBe('2027-03-01T00:00:00.000Z')
  })

  it('rejects plugin models missing from the declarations at init', async () => {
    const partial = createBetterAuthEngine({
      getPayload: () => Promise.resolve(payload),
      customFields: { session: [{ name: 'activeOrganizationId', type: 'text' }] },
      customModels: [
        {
          model: 'organization',
          fields: [
            { name: 'name', type: 'text' },
            { name: 'slug', type: 'text' },
            { name: 'logo', type: 'text' },
            { name: 'metadata', type: 'text' },
          ],
        },
      ],
      options: {
        baseURL: ORIGIN,
        trustedOrigins: [ORIGIN],
        secret: SECRET,
        emailAndPassword: { enabled: true, requireEmailVerification: false },
        plugins: [organization()],
      },
    })
    await expect(partial.auth.$context).rejects.toThrow(UnsupportedSchemaError)
    await expect(partial.auth.$context).rejects.toThrow('model "member" is not declared')
  })
})

describe('custom schema fail-fasts', () => {
  it('rejects undeclared extras instead of silently dropping them', async () => {
    const bare = createBetterAuthEngine({
      getPayload: () => Promise.resolve(payload),
      options: {
        baseURL: ORIGIN,
        trustedOrigins: [ORIGIN],
        secret: SECRET,
        emailAndPassword: { enabled: true, requireEmailVerification: false },
        user: { additionalFields: { favoriteColor: { type: 'string', required: false } } },
      },
    })
    await expect(bare.auth.$context).rejects.toThrow(UnsupportedSchemaError)
    await expect(bare.auth.$context).rejects.toThrow('user.favoriteColor')
  })

  it('rejects declared-but-absent names as probable typos', async () => {
    const typo = createBetterAuthEngine({
      getPayload: () => Promise.resolve(payload),
      customFields: { user: [{ name: 'favoriteColour', type: 'text' }] },
      options: {
        baseURL: ORIGIN,
        trustedOrigins: [ORIGIN],
        secret: SECRET,
        emailAndPassword: { enabled: true, requireEmailVerification: false },
        user: { additionalFields: { favoriteColor: { type: 'string', required: false } } },
      },
    })
    // Both directions fire: the schema extra is undeclared AND the
    // declaration is absent — either message proves fail-fast.
    await expect(typo.auth.$context).rejects.toThrow(UnsupportedSchemaError)
  })
})
