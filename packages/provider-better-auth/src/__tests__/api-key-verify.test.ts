/**
 * Issue #88 regressions on a REAL engine (real Better Auth + the real
 * `@better-auth/api-key` satellite on real Payload storage, SQLite in
 * memory) — no mocked API responses:
 *
 * 1. `authLinkServer(payload).verifyApiKey` resolves a valid 1.7.x key.
 *    The satellite names the owner `referenceId`; the port used to
 *    demand `userId` and threw for every valid key.
 * 2. A provider-side email verification of the address a linked user
 *    ALREADY carries (the post-import verification) grants the bound
 *    linking proof and sets the host's verified mirror
 *    (`emailVerifiedField`); it used to change nothing.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { apiKey } from '@better-auth/api-key'
import { organization } from 'better-auth/plugins/organization'
import { authLink, authLinkServer } from '@payload-auth-link/plugin'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { UnsupportedApiKeyOwnerError } from '../errors.js'

const ORIGIN = 'http://api-key-verify.test'
const SECRET = 'api-key-verify-integration-secret!!'

let payload: Payload
let latePayload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  autoDeclare: true,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: { enabled: false },
    plugins: [
      organization(),
      apiKey([
        { configId: 'default', defaultPrefix: 'pal_', enableMetadata: true },
        // Organization-owned keys: `referenceId` is an ORGANIZATION id.
        { configId: 'org', defaultPrefix: 'org_', references: 'organization' },
      ]),
    ],
  },
})

async function signUp(email: string): Promise<string> {
  const response = await engine.auth.handler(
    new Request(`${ORIGIN}/api/auth/sign-up/email`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({ name: email, email, password: 'correct-horse-battery' }),
    })
  )
  expect(response.status).toBe(200)
  const body = (await response.json()) as { user?: { id?: unknown } }
  const id = body.user?.id
  if (typeof id !== 'string' || id === '') {
    throw new Error('sign-up returned no user id')
  }
  return id
}

beforeAll(async () => {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      {
        slug: 'users',
        auth: true,
        // The host's own verified mirror (payload-auth's layout keeps
        // one); the plugin writes it only through emailVerifiedField.
        fields: [{ name: 'emailVerified', type: 'checkbox', defaultValue: false }],
      },
      ...engine.collections,
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [engine.provider],
        emailVerifiedField: 'emailVerified',
      }),
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
}, 120_000)

describe('verifyApiKey on @better-auth/api-key 1.7.x (#88)', () => {
  it('resolves a valid key to its owner through authLinkServer', async () => {
    const userId = await signUp('key-owner@test.dev')
    const created = (await engine.auth.api.createApiKey({
      body: { userId, name: 'ci key', metadata: { purpose: 'ci' } },
    })) as { key?: unknown }
    const key = typeof created.key === 'string' ? created.key : ''
    expect(key.startsWith('pal_')).toBe(true)

    const verified = await authLinkServer(payload).verifyApiKey(key)
    expect(verified).not.toBeNull()
    expect(verified?.userId).toBe(userId)
    expect(verified?.name).toBe('ci key')
    expect(verified?.prefix).toBe('pal_')
    expect(verified?.metadata).toEqual({ purpose: 'ci' })
  })

  it('refuses an organization-owned key instead of returning the org id as userId (#110)', async () => {
    const userId = await signUp('org-key-owner@test.dev')
    const org = (await engine.auth.api.createOrganization({
      body: { name: 'Key Org', slug: 'key-org', userId },
    })) as { id?: unknown } | null
    const organizationId = typeof org?.id === 'string' ? org.id : ''
    expect(organizationId).not.toBe('')
    const created = (await engine.auth.api.createApiKey({
      body: { configId: 'org', organizationId, userId, name: 'org key' },
    })) as { key?: unknown; referenceId?: unknown }
    const key = typeof created.key === 'string' ? created.key : ''
    expect(key.startsWith('org_')).toBe(true)
    // The satellite itself accepts the key and names the ORG as owner.
    expect(created.referenceId).toBe(organizationId)

    const verify = engine.provider.verifyApiKey
    if (verify === undefined) {
      throw new Error('the better-auth provider cannot verify API keys')
    }
    const verified = await verify(key)
    expect(verified.isErr()).toBe(true)
    const error = verified.isErr() ? verified.error : null
    expect(error).toBeInstanceOf(UnsupportedApiKeyOwnerError)
    expect((error as UnsupportedApiKeyOwnerError | null)?.referenceId).toBe(organizationId)
    const thrown = await authLinkServer(payload)
      .verifyApiKey(key)
      .then(
        () => null,
        (rejection: unknown) => rejection
      )
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).message).toMatch(/organization-owned/)
    // The typed refusal survives the server surface as the cause.
    expect((thrown as Error).cause).toBeInstanceOf(UnsupportedApiKeyOwnerError)
  })

  it('refuses a key whose owner user no longer exists (#110)', async () => {
    const userId = await signUp('gone-key-owner@test.dev')
    const created = (await engine.auth.api.createApiKey({
      body: { userId, name: 'orphan' },
    })) as { key?: unknown }
    const key = typeof created.key === 'string' ? created.key : ''
    const ctx = await engine.auth.$context
    await ctx.internalAdapter.deleteUser(userId)
    const verify = engine.provider.verifyApiKey
    if (verify === undefined) {
      throw new Error('the better-auth provider cannot verify API keys')
    }
    const verified = await verify(key)
    // BA keeps verifying the orphaned key; the owner gate refuses it —
    // never a verification naming a missing user.
    expect(verified.isErr() ? verified.error : null).toBeInstanceOf(UnsupportedApiKeyOwnerError)
  })

  it('narrows an unknown key to null instead of throwing', async () => {
    await expect(authLinkServer(payload).verifyApiKey('pal_not-a-real-key')).resolves.toBeNull()
  })
})

describe('verified-email sync onto an already-linked user (#88)', () => {
  it('a later provider verification grants the bound proof and the host mirror', async () => {
    const email = 'late-verify@test.dev'
    const baUserId = await signUp(email)
    // The import-mode state: the host document exists, is pre-linked to
    // the BA user by identity, and came in UNVERIFIED (no linking proof,
    // host mirror false).
    const host = await payload.create({
      collection: 'users',
      data: {
        email,
        password: 'unused-local-password-1',
        emailVerified: false,
        identities: [
          {
            providerId: 'better-auth',
            providerUserId: baUserId,
            email,
            linkedAt: new Date().toISOString(),
          },
        ],
      },
      overrideAccess: true,
    })
    await payload.update({
      collection: 'users',
      id: host.id,
      data: { linkable: false, linkableEmail: null },
      overrideAccess: true,
    })

    // Better Auth's own update path (hooks run) verifies the address.
    const ctx = await engine.auth.$context
    await ctx.internalAdapter.updateUser(baUserId, { emailVerified: true })

    const after = (await payload.findByID({
      collection: 'users',
      id: host.id,
      depth: 0,
      overrideAccess: true,
    })) as unknown as Record<string, unknown>
    expect(after['emailVerified']).toBe(true)
    expect(after['linkable']).toBe(true)
    expect(after['linkableEmail']).toBe(email)
  })

  it('an unverified provider update leaves the proof and the mirror alone', async () => {
    const email = 'still-unverified@test.dev'
    const baUserId = await signUp(email)
    const host = await payload.create({
      collection: 'users',
      data: {
        email,
        password: 'unused-local-password-1',
        emailVerified: false,
        identities: [
          {
            providerId: 'better-auth',
            providerUserId: baUserId,
            email,
            linkedAt: new Date().toISOString(),
          },
        ],
      },
      overrideAccess: true,
    })
    await payload.update({
      collection: 'users',
      id: host.id,
      data: { linkable: false, linkableEmail: null },
      overrideAccess: true,
    })
    const ctx = await engine.auth.$context
    await ctx.internalAdapter.updateUser(baUserId, { name: 'Renamed' })
    const after = (await payload.findByID({
      collection: 'users',
      id: host.id,
      depth: 0,
      overrideAccess: true,
    })) as unknown as Record<string, unknown>
    expect(after['emailVerified']).toBe(false)
    expect(after['linkable']).toBe(false)
  })
})
