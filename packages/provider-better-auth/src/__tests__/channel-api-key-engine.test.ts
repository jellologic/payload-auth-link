/**
 * Credential-path matrix row 2 (docs/security-model.md), api-key half,
 * on a REAL Better Auth engine: the real `@better-auth/api-key`
 * satellite with `enableSessionForAPIKeys` turns an `x-api-key` header
 * into a session, the port observes the `api-key` channel, and the
 * host ADMITS it (`admitChannels: ['cookie', 'api-key']`). BA's
 * `bearer()` plugin is installed too, but its channel is NOT admitted,
 * so a valid bearer session is refused here (the admitted bearer walk
 * is `channel-bearer-engine.test.ts`).
 *
 * Success AND failure paths: an unknown, a disabled, an expired and a
 * deleted key, another user's key, a suspended user, an unproven email,
 * and CSRF (only bearer is Origin-exempt; an api-key logout without
 * Origin is still refused).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { apiKey } from '@better-auth/api-key'
import { authLink } from '@payload-auth-link/plugin'
import { bearer } from 'better-auth/plugins'
import { buildConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { createHarness, createPayloadRef, PAST, PASSWORD } from './engine-harness.js'

const ORIGIN = 'http://channel-api-key-ba.test'
const SECRET = 'channel-api-key-ba-engine-secret!!!'

const ref = createPayloadRef()
const engine = createBetterAuthEngine({
  getPayload: ref.getPayload,
  autoDeclare: true,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    plugins: [
      bearer(),
      apiKey({
        defaultPrefix: 'pal_',
        enableSessionForAPIKeys: true,
        rateLimit: { enabled: false },
      }),
    ],
  },
})
const h = createHarness({ origin: ORIGIN, engine, ref })

/** A real key minted by the satellite for a BA user. */
async function mintKey(email: string): Promise<{ key: string; keyId: string }> {
  const created = (await engine.auth.api.createApiKey({
    body: { userId: await h.baUserId(email) },
  })) as { key?: unknown; id?: unknown }
  if (typeof created.key !== 'string' || typeof created.id !== 'string') {
    throw new Error('createApiKey returned no key')
  }
  return { key: created.key, keyId: created.id }
}

function withKey(key: string): { headers: Record<string, string> } {
  return { headers: { 'x-api-key': key } }
}

function sessionWithKey(key: string) {
  return h.rest('GET', '/auth-link/session', withKey(key))
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
  const updated = await h.live().update({
    collection: apiKeySlug(),
    where: { baId: { equals: keyId } },
    data,
    overrideAccess: true,
  })
  expect(updated.docs).toHaveLength(1)
}

beforeAll(async () => {
  await h.boot(
    await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          providers: [engine.provider],
          admitChannels: ['cookie', 'api-key'],
        }),
      ],
    })
  )
  await engine.auth.$context
}, 120_000)

describe('row 2: an admitted api-key channel on real Better Auth', () => {
  it('success: a real key resolves its linked user on the session endpoint and REST reads', async () => {
    const email = 'key-ok@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const { key } = await mintKey(email)
    const reply = await sessionWithKey(key)
    expect(reply.status).toBe(200)
    expect(h.userIdOf(reply)).toBe(id)
    expect(await h.readsDoc(withKey(key), id)).toBe(true)
  })

  it('failure: an unknown key authenticates nothing', async () => {
    expect((await sessionWithKey('pal_not-a-real-key-0123456789')).status).toBe(401)
  })

  it("failure: each key resolves only its owner (never another user's)", async () => {
    const alice = await h.linkedUser('key-alice@ba-channel.test')
    const bob = await h.linkedUser('key-bob@ba-channel.test')
    const aliceKey = (await mintKey('key-alice@ba-channel.test')).key
    const bobKey = (await mintKey('key-bob@ba-channel.test')).key
    expect(h.userIdOf(await sessionWithKey(aliceKey))).toBe(alice.id)
    expect(h.userIdOf(await sessionWithKey(bobKey))).toBe(bob.id)
    // Bob's key next to Alice's cookie: the presented key decides.
    const mixed = await h.rest('GET', '/auth-link/session', {
      cookie: alice.cookie,
      ...withKey(bobKey),
    })
    expect(h.userIdOf(mixed)).toBe(bob.id)
    expect(await h.readsDoc(withKey(aliceKey), bob.id)).toBe(false)
  })

  it('failure: a disabled key is refused', async () => {
    const email = 'key-disabled@ba-channel.test'
    await h.linkedUser(email)
    const { key, keyId } = await mintKey(email)
    expect((await sessionWithKey(key)).status).toBe(200)
    await updateKeyRow(keyId, { enabled: false })
    expect((await sessionWithKey(key)).status).toBe(401)
  })

  it('failure: an expired key is refused', async () => {
    const email = 'key-expired@ba-channel.test'
    await h.linkedUser(email)
    const { key, keyId } = await mintKey(email)
    await updateKeyRow(keyId, { expiresAt: PAST })
    expect((await sessionWithKey(key)).status).toBe(401)
  })

  it('failure: a deleted (revoked) key is refused; a sibling key survives', async () => {
    const email = 'key-revoked@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const first = await mintKey(email)
    const second = await mintKey(email)
    await h.live().delete({
      collection: apiKeySlug(),
      where: { baId: { equals: first.keyId } },
      overrideAccess: true,
    })
    expect((await sessionWithKey(first.key)).status).toBe(401)
    expect(h.userIdOf(await sessionWithKey(second.key))).toBe(id)
  })

  it("failure: a suspended user's key is refused on the next request", async () => {
    const email = 'key-suspended@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const { key } = await mintKey(email)
    expect(await h.readsDoc(withKey(key), id)).toBe(true)
    await h.suspend(id)
    expect((await sessionWithKey(key)).status).toBe(401)
    expect(await h.readsDoc(withKey(key), id)).toBe(false)
  })

  it('failure: a key for an unproven (BA-unverified) email never links or provisions', async () => {
    const email = 'key-unverified@ba-channel.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    await h.signUp(email)
    const { key } = await mintKey(email)
    expect((await sessionWithKey(key)).status).toBe(401)
    expect(h.identitiesOf(await h.hostDoc(id))).toEqual([])
    const fresh = 'key-unverified-new@ba-channel.test'
    await h.signUp(fresh)
    expect((await sessionWithKey((await mintKey(fresh)).key)).status).toBe(401)
    expect(await h.hostDocByEmail(fresh)).toBeUndefined()
  })

  it('CSRF: an api-key logout without Origin is refused (only bearer is Origin-exempt)', async () => {
    const email = 'key-logout@ba-channel.test'
    await h.linkedUser(email)
    const { key } = await mintKey(email)
    const refused = await h.rest('DELETE', '/auth-link/session', { csrf: false, ...withKey(key) })
    expect(refused.status).toBe(403)
    expect((await sessionWithKey(key)).status).toBe(200)
  })

  it('failure: a valid bearer session is refused — the bearer channel is not admitted', async () => {
    const email = 'key-host-bearer@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const signIn = await h.baPost('/sign-in/email', { email, password: PASSWORD })
    const token = signIn.headers.get('set-auth-token') ?? ''
    expect(token).not.toBe('')
    const bearer = { authorization: `Bearer ${token}` }
    expect((await h.rest('GET', '/auth-link/session', bearer)).status).toBe(401)
    expect(await h.readsDoc(bearer, id)).toBe(false)
  })
})
