/**
 * Credential-path matrix row 22 (docs/security-model.md) on a host
 * WITHOUT Payload's server-side sessions (`auth.useSessions: false`),
 * on a REAL Better Auth engine: the pre-link local JWT is stateless,
 * so clearing the sessions array cannot reach it — the provider-owned
 * local-JWT gate refuses it on the next operation instead. The
 * `useSessions` host is walked in `credential-paths-rest-engine.test.ts`.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { buildConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { createHarness, createPayloadRef } from './engine-harness.js'

const ORIGIN = 'http://prelink-stateless-ba.test'
const SECRET = 'prelink-stateless-ba-engine-secret!'

const ref = createPayloadRef()
const engine = createBetterAuthEngine({
  getPayload: ref.getPayload,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})
const h = createHarness({ origin: ORIGIN, engine, ref })

beforeAll(async () => {
  await h.boot(
    await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      collections: [
        { slug: 'users', auth: { useSessions: false }, fields: [] },
        ...engine.collections,
      ],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          providers: [engine.provider],
        }),
      ],
    })
  )
  await engine.auth.$context
}, 120_000)

describe('row 22: stateless local JWTs issued before a real BA link', () => {
  it('work before the link, and are refused on every operation once BA links the document', async () => {
    const email = 'stateless@ba-prelink.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    const jwt = h.jwtCookieOf(await h.localLogin(email))
    expect(await h.readsDoc({ cookie: jwt }, id)).toBe(true)
    expect(await h.hostIdOf(await h.verifiedSession(email))).toBe(id)
    // The JWT resolves no user at authentication (GHSA-mjvh): anonymous.
    expect((await h.rest('GET', `/users/${id}`, { cookie: jwt })).status).toBe(403)
    const write = await h.rest('PATCH', `/users/${id}`, {
      cookie: jwt,
      body: { email: 'moved@ba-prelink.test' },
    })
    expect(write.status).toBe(403)
    expect((await h.hostDoc(id)).email).toBe(email)
    expect((await h.localLogin(email)).status).toBe(403)
  })

  it('failure: an unverified BA sign-up links nothing, so the stateless JWT keeps working', async () => {
    const email = 'stateless-unverified@ba-prelink.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    const jwt = h.jwtCookieOf(await h.localLogin(email))
    expect((await h.pluginSession(await h.signUp(email))).status).toBe(401)
    expect(await h.readsDoc({ cookie: jwt }, id)).toBe(true)
  })

  it('failure: a suspended stateless JWT is refused even before any link', async () => {
    const email = 'stateless-suspended@ba-prelink.test'
    const id = await h.createDoc(email)
    const jwt = h.jwtCookieOf(await h.localLogin(email))
    await h.suspend(id)
    expect((await h.rest('GET', `/users/${id}`, { cookie: jwt })).status).toBe(403)
  })
})
