/**
 * Credential-path matrix row 2 (docs/security-model.md), bearer half,
 * on a REAL Better Auth engine: BA's own `bearer()` plugin turns an
 * `Authorization: Bearer [REDACTED]` token into its session, the port
 * observes the `bearer` channel, and the host ADMITS it
 * (`admitChannels: ['cookie', 'bearer']`). The api-key satellite is
 * installed too (`enableSessionForAPIKeys`) but its channel is NOT
 * admitted, so a valid key session is refused here (the admitted
 * api-key walk is `channel-api-key-engine.test.ts`; the default
 * cookie-only refusal is in `credential-paths-rest-engine.test.ts`).
 *
 * Success AND failure paths: a forged / tampered token, an expired and
 * a revoked session, another user's token, a suspended user, an
 * unproven email, and the channel-aware CSRF rule (bearer is exempt
 * from the Origin check only because it is admitted; cookies are not).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { apiKey } from '@better-auth/api-key'
import { authLink, authLinkServer } from '@payload-auth-link/plugin'
import { bearer } from 'better-auth/plugins'
import { buildConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { createHarness, createPayloadRef, PAST, PASSWORD } from './engine-harness.js'

const ORIGIN = 'http://channel-bearer-ba.test'
const SECRET = 'channel-bearer-ba-engine-secret!!!!'

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
    plugins: [bearer(), apiKey({ enableSessionForAPIKeys: true })],
  },
})
const h = createHarness({ origin: ORIGIN, engine, ref })

/** The `set-auth-token` BA's bearer plugin returns on sign-in. */
async function bearerSignIn(email: string): Promise<string> {
  const response = await h.baPost('/sign-in/email', { email, password: PASSWORD })
  expect(response.status).toBe(200)
  const token = response.headers.get('set-auth-token')
  if (token === null || token === '') {
    throw new Error('the bearer plugin returned no set-auth-token')
  }
  return token
}

function asBearer(token: string): { authorization: string } {
  return { authorization: `Bearer ${token}` }
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
          admitChannels: ['cookie', 'bearer'],
        }),
      ],
    })
  )
  await engine.auth.$context
}, 120_000)

describe('row 2: an admitted bearer channel on real Better Auth', () => {
  it('success: a bearer token (no cookie) resolves its linked user; collection reads and /access see it', async () => {
    const { id } = await h.linkedUser('bearer-ok@ba-channel.test', { roles: ['admin'] })
    const token = await bearerSignIn('bearer-ok@ba-channel.test')
    const reply = await h.rest('GET', '/auth-link/session', asBearer(token))
    expect(reply.status).toBe(200)
    expect(h.userIdOf(reply)).toBe(id)
    const read = await h.rest('GET', `/users/${id}`, asBearer(token))
    expect(read.status).toBe(200)
    expect(String((read.body as { id?: unknown }).id)).toBe(id)
    expect((await h.accessOf(asBearer(token))).canAccessAdmin).toBe(true)
  })

  // Found by this walk: Payload's `me` operation decoded the provider's
  // opaque bearer token as a Payload JWT (a 500) and would echo it back
  // as `token`. The plugin's `me` hook answers for auth-link users.
  it('success: /users/me answers for an admitted bearer session', async () => {
    const email = 'bearer-me@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const token = await bearerSignIn(email)
    const me = await h.rest('GET', '/users/me', asBearer(token))
    expect(me.status).toBe(200)
    expect(h.userIdOf(me)).toBe(id)
    // The provider's token is never echoed back as Payload's.
    expect((me.body as { token?: unknown }).token).toBeUndefined()
    expect(typeof (me.body as { exp?: unknown }).exp).toBe('number')
  })

  it('failure: a tampered (bad-signature) bearer token authenticates nothing', async () => {
    const { id } = await h.linkedUser('bearer-tamper@ba-channel.test')
    const token = await bearerSignIn('bearer-tamper@ba-channel.test')
    const [raw] = token.split('.')
    const forged = `${raw ?? ''}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
    expect((await h.rest('GET', '/auth-link/session', asBearer(forged))).status).toBe(401)
    expect(await h.readsDoc(asBearer(forged), id)).toBe(false)
    expect(
      (await h.rest('GET', '/auth-link/session', asBearer('not-a-session-token'))).status
    ).toBe(401)
  })

  it("failure: each bearer token resolves only its own user (never another user's)", async () => {
    const alice = await h.linkedUser('bearer-alice@ba-channel.test')
    const bob = await h.linkedUser('bearer-bob@ba-channel.test')
    const aliceToken = await bearerSignIn('bearer-alice@ba-channel.test')
    const bobToken = await bearerSignIn('bearer-bob@ba-channel.test')
    expect(h.userIdOf(await h.rest('GET', '/auth-link/session', asBearer(aliceToken)))).toBe(
      alice.id
    )
    expect(h.userIdOf(await h.rest('GET', '/auth-link/session', asBearer(bobToken)))).toBe(bob.id)
    // Bob's token alongside Alice's cookie: the presented bearer wins
    // (BA overwrites the cookie), so the request is Bob's — never a
    // merge, and never Alice's grants under Bob's credential.
    const mixed = await h.rest('GET', '/auth-link/session', {
      cookie: alice.cookie,
      ...asBearer(bobToken),
    })
    expect(h.userIdOf(mixed)).toBe(bob.id)
  })

  it('failure: an expired session is refused on the bearer channel', async () => {
    const email = 'bearer-expired@ba-channel.test'
    await h.linkedUser(email)
    const token = await bearerSignIn(email)
    await h.live().update({
      collection: 'ba-sessions',
      where: { token: { equals: token.split('.')[0] ?? '' } },
      data: { expiresAt: PAST },
      overrideAccess: true,
    })
    expect((await h.rest('GET', '/auth-link/session', asBearer(token))).status).toBe(401)
  })

  it('failure: a revoked session is refused; the sibling bearer session survives', async () => {
    const email = 'bearer-revoked@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const first = await bearerSignIn(email)
    const second = await bearerSignIn(email)
    const signOut = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-out`, {
        method: 'POST',
        headers: { origin: ORIGIN, ...asBearer(first) },
      })
    )
    expect(signOut.status).toBe(200)
    expect((await h.rest('GET', '/auth-link/session', asBearer(first))).status).toBe(401)
    expect(h.userIdOf(await h.rest('GET', '/auth-link/session', asBearer(second)))).toBe(id)
  })

  it('failure: a suspended user is refused on the bearer channel', async () => {
    const email = 'bearer-suspended@ba-channel.test'
    const { id } = await h.linkedUser(email)
    const token = await bearerSignIn(email)
    await h.suspend(id)
    expect((await h.rest('GET', '/auth-link/session', asBearer(token))).status).toBe(401)
    expect(await h.readsDoc(asBearer(token), id)).toBe(false)
  })

  it('failure: an unproven (BA-unverified) email never links or provisions over bearer', async () => {
    const email = 'bearer-unverified@ba-channel.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    await h.signUp(email)
    const token = await bearerSignIn(email)
    expect((await h.rest('GET', '/auth-link/session', asBearer(token))).status).toBe(401)
    expect(h.identitiesOf(await h.hostDoc(id))).toEqual([])
    const fresh = 'bearer-unverified-new@ba-channel.test'
    await h.signUp(fresh)
    const freshToken = await bearerSignIn(fresh)
    expect((await h.rest('GET', '/auth-link/session', asBearer(freshToken))).status).toBe(401)
    expect(await h.hostDocByEmail(fresh)).toBeUndefined()
  })

  it('CSRF: an admitted bearer logout needs no Origin; a cookie logout without Origin is 403', async () => {
    const email = 'bearer-logout@ba-channel.test'
    const { cookie } = await h.linkedUser(email)
    const refused = await h.rest('DELETE', '/auth-link/session', { cookie, csrf: false })
    expect(refused.status).toBe(403)
    await h.hostIdOf(cookie)
    const token = await bearerSignIn(email)
    const done = await h.rest('DELETE', '/auth-link/session', { csrf: false, ...asBearer(token) })
    expect(done.status).toBe(200)
    expect((await h.rest('GET', '/auth-link/session', asBearer(token))).status).toBe(401)
    // Only the presented session ended.
    await h.hostIdOf(cookie)
  })

  it('failure: a valid api-key session is refused — the api-key channel is not admitted', async () => {
    const email = 'bearer-host-key@ba-channel.test'
    const { id, cookie } = await h.linkedUser(email)
    const created = (await engine.auth.api.createApiKey({
      body: { userId: await h.baUserId(email) },
    })) as { key?: unknown }
    const key = typeof created.key === 'string' ? created.key : ''
    expect(await authLinkServer(h.live()).verifyApiKey(key)).not.toBeNull()
    const reply = await h.rest('GET', '/auth-link/session', { headers: { 'x-api-key': key } })
    expect(reply.status).toBe(401)
    expect(await h.readsDoc({ headers: { 'x-api-key': key } }, id)).toBe(false)
    // The key never rides along on a cookie either: the presented key
    // decides the channel (fail-closed), so the cookie user is refused.
    expect(
      (await h.rest('GET', '/auth-link/session', { cookie, headers: { 'x-api-key': key } })).status
    ).toBe(401)
  })
})
