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
import { authLink, authLinkServer } from '@payload-auth-link/plugin'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

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
    plugins: [apiKey({ defaultPrefix: 'pal_', enableMetadata: true })],
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

/** A real key minted by the satellite for a BA user. */
async function mintKey(userId: string): Promise<{ key: string; keyId: string }> {
  const created = (await engine.auth.api.createApiKey({ body: { userId } })) as {
    key?: unknown
    id?: unknown
  }
  if (typeof created.key !== 'string' || typeof created.id !== 'string') {
    throw new Error('createApiKey returned no key')
  }
  return { key: created.key, keyId: created.id }
}

/** The satellite's `apikey` model, served from a derived collection. */
function apiKeySlug(): string {
  const slug = engine.collections.map((c) => c.slug).find((s) => /api-?key/i.test(s))
  if (slug === undefined) {
    throw new Error('no api-key collection derived')
  }
  return slug
}

async function updateKeyRow(keyId: string, data: Record<string, unknown>): Promise<void> {
  const updated = await payload.update({
    collection: apiKeySlug(),
    where: { baId: { equals: keyId } },
    data,
    overrideAccess: true,
  })
  expect(updated.docs).toHaveLength(1)
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

  it('narrows an unknown key to null instead of throwing', async () => {
    await expect(authLinkServer(payload).verifyApiKey('pal_not-a-real-key')).resolves.toBeNull()
  })

  // Matrix row 20 failure paths on the real satellite: the key's state
  // lives in the provider's own store (the derived api-key collection),
  // so each case flips that row and re-verifies the SAME key.
  it('refuses a disabled key (null), after it verified while enabled', async () => {
    const userId = await signUp('key-disabled@test.dev')
    const { key, keyId } = await mintKey(userId)
    expect((await authLinkServer(payload).verifyApiKey(key))?.userId).toBe(userId)
    await updateKeyRow(keyId, { enabled: false })
    await expect(authLinkServer(payload).verifyApiKey(key)).resolves.toBeNull()
  })

  it('refuses an expired key (null)', async () => {
    const userId = await signUp('key-expired@test.dev')
    const { key, keyId } = await mintKey(userId)
    await updateKeyRow(keyId, { expiresAt: '2020-01-01T00:00:00.000Z' })
    await expect(authLinkServer(payload).verifyApiKey(key)).resolves.toBeNull()
  })

  it('refuses a deleted key (null); a sibling key of the same owner still verifies', async () => {
    const userId = await signUp('key-deleted@test.dev')
    const first = await mintKey(userId)
    const second = await mintKey(userId)
    const removed = await payload.delete({
      collection: apiKeySlug(),
      where: { baId: { equals: first.keyId } },
      overrideAccess: true,
    })
    expect(removed.docs).toHaveLength(1)
    await expect(authLinkServer(payload).verifyApiKey(first.key)).resolves.toBeNull()
    expect((await authLinkServer(payload).verifyApiKey(second.key))?.userId).toBe(userId)
  })

  it("resolves each key to its own owner, never another user's", async () => {
    const alice = await signUp('key-alice@test.dev')
    const bob = await signUp('key-bob@test.dev')
    const aliceKey = await mintKey(alice)
    const bobKey = await mintKey(bob)
    const server = authLinkServer(payload)
    expect((await server.verifyApiKey(aliceKey.key))?.userId).toBe(alice)
    expect((await server.verifyApiKey(bobKey.key))?.userId).toBe(bob)
    // A key one character off another user's key is unknown, not theirs.
    const tampered = `${bobKey.key.slice(0, -1)}${bobKey.key.endsWith('a') ? 'b' : 'a'}`
    await expect(server.verifyApiKey(tampered)).resolves.toBeNull()
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
