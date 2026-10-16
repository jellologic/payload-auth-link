/**
 * Credential-path matrix rows 2 (default channel policy), 3–7, 10, 10a, 16,
 * 22–27 (docs/security-model.md) on a REAL Better Auth engine — real
 * BA 1.7 on real Payload storage (SQLite in memory) behind a real
 * authLink boot. Until issue #84 these rows were pinned on Better Auth
 * by the stub provider only; this mirrors the Auth.js walk
 * (`provider-authjs/src/__tests__/credential-paths-engine.test.ts`).
 *
 * Every row walks its success path AND its failure paths: wrong
 * password, a suspended user, expired / revoked sessions, another
 * user's credential, an unproven email, a pre-link local JWT, and a
 * missing CSRF proof.
 *
 * The admitted bearer / api-key channels are walked in
 * `channel-bearer-engine.test.ts` / `channel-api-key-engine.test.ts`;
 * row 22 on a host without `useSessions` in
 * `prelink-jwt-stateless-engine.test.ts` (one Payload per file).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { createSessionVerifier } from '@payload-auth-link/web'
import { bearer } from 'better-auth/plugins'
import { buildConfig, handleEndpoints } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import {
  createHarness,
  createPayloadRef,
  PASSWORD,
  PAST,
  SUSPENDED_UNTIL,
} from './engine-harness.js'

const ORIGIN = 'http://credential-paths-rest-ba.test'
const SECRET = 'credential-paths-rest-ba-secret!!!!'

const ref = createPayloadRef()
const engine = createBetterAuthEngine({
  getPayload: ref.getPayload,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    // BA's bearer plugin is installed, but the host keeps the default
    // cookie-only channel policy (row 2).
    plugins: [bearer()],
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
        // A host-enabled API key channel (row 10).
        { slug: 'users', auth: { useAPIKey: true }, fields: [] },
        { slug: 'pages', fields: [{ name: 'title', type: 'text', required: true }] },
        ...engine.collections,
      ],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          providers: [engine.provider],
          organizations: { enabled: true },
        }),
      ],
    })
  )
  await engine.auth.$context
}, 120_000)

describe('row 2: default channel policy (cookie-only) on real Better Auth', () => {
  it('success: the cookie channel resolves; failure: the same live session over bearer is refused', async () => {
    const email = 'default-channel@ba-rest.test'
    const { id, cookie } = await h.linkedUser(email)
    const signIn = await h.baPost('/sign-in/email', { email, password: PASSWORD })
    const token = signIn.headers.get('set-auth-token') ?? ''
    expect(token).not.toBe('')
    const bearerAuth = { authorization: `Bearer ${token}` }
    expect((await h.rest('GET', '/auth-link/session', bearerAuth)).status).toBe(401)
    expect(await h.readsDoc(bearerAuth, id)).toBe(false)
    // A bearer header next to a valid cookie still decides the channel
    // (fail-closed): refused, not silently served from the cookie.
    expect((await h.rest('GET', '/auth-link/session', { cookie, ...bearerAuth })).status).toBe(401)
    expect(await h.hostIdOf(cookie)).toBe(id)
  })

  it('failure: a bearer logout without Origin is CSRF-refused when bearer is not admitted', async () => {
    const email = 'default-channel-logout@ba-rest.test'
    const { cookie } = await h.linkedUser(email)
    const signIn = await h.baPost('/sign-in/email', { email, password: PASSWORD })
    const token = signIn.headers.get('set-auth-token') ?? ''
    const refused = await h.rest('DELETE', '/auth-link/session', {
      csrf: false,
      authorization: `Bearer ${token}`,
    })
    expect(refused.status).toBe(403)
    await h.hostIdOf(cookie)
  })
})

describe('rows 3–7 and 22: local credentials on a BA-linked document', () => {
  const email = 'provider-owned@ba-rest.test'
  const operator = 'operator@ba-rest.test'
  let id = ''
  let preLinkJwt = ''

  beforeAll(async () => {
    id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    // Row 22: a local JWT minted while the document was still unlinked.
    const login = await h.localLogin(email)
    expect(login.status).toBe(200)
    preLinkJwt = h.jwtCookieOf(login)
    expect(await h.meId({ cookie: preLinkJwt })).toBe(id)
    expect(await h.hostIdOf(await h.verifiedSession(email))).toBe(id)
    await h.createDoc(operator, { roles: ['admin'] })
    await h.live().update({
      collection: 'users',
      id,
      data: { resetPasswordToken: 'linked-reset-token', resetPasswordExpiration: SUSPENDED_UNTIL },
      overrideAccess: true,
    })
  })

  it('row 22: the pre-link local JWT is dead after the BA link', async () => {
    expect(await h.meId({ cookie: preLinkJwt })).toBeNull()
    const write = await h.rest('POST', '/pages', { cookie: preLinkJwt, body: { title: 'nope' } })
    expect([401, 403]).toContain(write.status)
    expect(await h.readsDoc({ cookie: preLinkJwt }, id)).toBe(false)
  })

  it('row 3: local login is refused (403) on the linked document; an operator keeps it', async () => {
    expect((await h.localLogin(email)).status).toBe(403)
    expect((await h.localLogin(operator)).status).toBe(200)
    expect((await h.localLogin(operator, 'wrong-password-1')).status).toBe(401)
    // The linked user's credential is the provider's: BA signs in.
    expect(await h.hostIdOf(await h.signIn(email))).toBe(id)
    expect((await h.baPost('/sign-in/email', { email, password: 'wrong-password-1' })).status).toBe(
      401
    )
  })

  it('rows 4 + 5: an operator JWT works and refreshes; the pre-link JWT cannot refresh', async () => {
    const jwt = h.jwtCookieOf(await h.localLogin(operator))
    expect((await h.rest('POST', '/pages', { cookie: jwt, body: { title: 'ok' } })).status).toBe(
      201
    )
    expect((await h.rest('POST', '/users/refresh-token', { cookie: jwt, body: {} })).status).toBe(
      200
    )
    const refreshed = await h.rest('POST', '/users/refresh-token', { cookie: preLinkJwt, body: {} })
    expect(refreshed.status).toBe(403)
  })

  it('rows 4 + 5: a suspended local JWT is refused on the next request and cannot refresh', async () => {
    const local = 'suspended-local@ba-rest.test'
    const localId = await h.createDoc(local)
    const jwt = h.jwtCookieOf(await h.localLogin(local))
    expect((await h.rest('POST', '/pages', { cookie: jwt, body: { title: 'y' } })).status).toBe(201)
    await h.suspend(localId)
    expect((await h.rest('POST', '/pages', { cookie: jwt, body: { title: 'x' } })).status).toBe(401)
    expect((await h.rest('POST', '/users/refresh-token', { cookie: jwt, body: {} })).status).toBe(
      401
    )
    expect((await h.localLogin(local)).status).toBe(401)
  })

  it('row 6: forgot-password is refused (403) on the linked document, allowed for the operator', async () => {
    expect((await h.rest('POST', '/users/forgot-password', { body: { email } })).status).toBe(403)
    const linked = await h.hostDoc(id)
    expect(linked.resetPasswordToken).toBe('linked-reset-token')
    expect(
      (await h.rest('POST', '/users/forgot-password', { body: { email: operator } })).status
    ).toBe(200)
  })

  it('row 7: a reset token minted before linking dies (403); the password never rotates', async () => {
    const reset = await h.rest('POST', '/users/reset-password', {
      body: { token: 'linked-reset-token', password: 'RotatedByReset-1' },
    })
    expect(reset.status).toBe(403)
    expect((await h.localLogin(email, 'RotatedByReset-1')).status).toBe(401)
    // The provider credential is untouched.
    expect(await h.hostIdOf(await h.signIn(email))).toBe(id)
    const wrong = await h.rest('POST', '/users/reset-password', {
      body: { token: 'no-such-token', password: 'RotatedByReset-1' },
    })
    expect(wrong.status).toBe(403)
  })

  it('row 7: a suspended unlinked user cannot reset into a session (401)', async () => {
    const local = 'suspended-reset@ba-rest.test'
    const localId = await h.createDoc(local)
    await h.live().update({
      collection: 'users',
      id: localId,
      data: {
        resetPasswordToken: 'suspended-reset-token',
        resetPasswordExpiration: SUSPENDED_UNTIL,
        suspendedUntil: SUSPENDED_UNTIL,
      },
      overrideAccess: true,
    })
    const reset = await h.rest('POST', '/users/reset-password', {
      body: { token: 'suspended-reset-token', password: 'RotatedSuspended-1' },
    })
    expect(reset.status).toBe(401)
    expect(reset.headers.get('set-cookie') ?? '').not.toMatch(/payload-token=[^;]/)
  })
})

describe('row 10: useAPIKey on an unlinked document', () => {
  it('an existing key works until the user is suspended, then 401 on the next request', async () => {
    const id = await h.createDoc('api-key@ba-rest.test')
    const key = 'ba-unlinked-api-key-0123456789abcdef'
    await h.live().update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: key },
      overrideAccess: true,
    })
    const authorization = `users API-Key ${key}`
    expect(await h.meId({ authorization })).toBe(id)
    expect((await h.rest('POST', '/pages', { authorization, body: { title: 'k' } })).status).toBe(
      201
    )
    await h.suspend(id)
    expect((await h.rest('POST', '/pages', { authorization, body: { title: 'k' } })).status).toBe(
      401
    )
    expect((await h.rest('PATCH', `/users/${id}`, { authorization, body: {} })).status).toBe(401)
  })

  it("failure: an unknown key is anonymous; a key reaches only its own user's grants", async () => {
    expect(await h.meId({ authorization: 'users API-Key not-a-real-key' })).toBeNull()
    expect(
      (
        await h.rest('POST', '/pages', {
          authorization: 'users API-Key not-a-real-key',
          body: { title: 'k' },
        })
      ).status
    ).toBe(403)
    const ownerId = await h.createDoc('api-key-owner@ba-rest.test')
    const other = await h.linkedUser('api-key-other@ba-rest.test')
    const key = 'ba-owner-api-key-0123456789abcdef0'
    await h.live().update({
      collection: 'users',
      id: ownerId,
      data: { enableAPIKey: true, apiKey: key },
      overrideAccess: true,
    })
    const authorization = `users API-Key ${key}`
    expect(await h.meId({ authorization })).toBe(ownerId)
    const hijack = await h.rest('PATCH', `/users/${other.id}`, {
      authorization,
      body: { email: 'hijacked@ba-rest.test' },
    })
    expect([403, 404]).toContain(hijack.status)
    expect((await h.hostDoc(other.id)).email).toBe('api-key-other@ba-rest.test')
  })
})

describe('row 10a: a Payload API key enabled before the BA link', () => {
  it('is cleared by the link and refused (403) afterwards, re-enabled or not', async () => {
    const email = 'pre-link-key@ba-rest.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    const key = 'ba-pre-link-api-key-0123456789abcdef'
    await h.live().update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: key },
      overrideAccess: true,
    })
    const authorization = `users API-Key ${key}`
    expect(await h.meId({ authorization })).toBe(id)
    expect(await h.readsDoc({ authorization }, id)).toBe(true)
    // The address owner signs in through Better Auth: the document links.
    expect(await h.hostIdOf(await h.verifiedSession(email))).toBe(id)
    expect((await h.hostDoc(id)).enableAPIKey).toBe(false)
    expect(await h.meId({ authorization })).toBeNull()
    expect((await h.rest('GET', `/users/${id}`, { authorization })).status).toBe(403)
    const write = await h.rest('PATCH', `/users/${id}`, {
      authorization,
      body: { email: 'moved@ba-rest.test' },
    })
    expect(write.status).toBe(403)
    expect((await h.rest('GET', '/users', { authorization })).status).toBe(403)
    // A key put back on the linked document is refused by the gate.
    const again = 'ba-re-enabled-api-key-0123456789abc'
    await h.live().update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: again },
      overrideAccess: true,
    })
    const reEnabled = `users API-Key ${again}`
    expect((await h.rest('GET', '/users/me', { authorization: reEnabled })).status).toBe(403)
    expect((await h.rest('GET', `/users/${id}`, { authorization: reEnabled })).status).toBe(403)
    expect(
      (await h.rest('POST', '/pages', { authorization: reEnabled, body: { title: 'k' } })).status
    ).toBe(403)
    expect((await h.hostDoc(id)).email).toBe(email)
    // The provider session is unaffected.
    expect(await h.hostIdOf(await h.signIn(email))).toBe(id)
  })
})

describe('row 16: /users/me and the /access map under a BA session', () => {
  it('success: an admin session sees itself and the admin grant; suspended sees neither', async () => {
    const { id, cookie } = await h.linkedUser('admin-me@ba-rest.test', { roles: ['admin'] })
    expect(await h.meId({ cookie })).toBe(id)
    expect((await h.accessOf({ cookie })).canAccessAdmin).toBe(true)
    await h.suspend(id)
    expect(await h.meId({ cookie })).toBeNull()
    expect((await h.accessOf({ cookie })).canAccessAdmin).toBeFalsy()
  })

  it('failure: a plain user holds no admin grant', async () => {
    const { id, cookie } = await h.linkedUser('plain-me@ba-rest.test')
    expect(await h.meId({ cookie })).toBe(id)
    expect((await h.accessOf({ cookie })).canAccessAdmin).toBeFalsy()
  })

  it('failure: an expired or revoked BA session sees neither', async () => {
    const email = 'expired-me@ba-rest.test'
    const { cookie } = await h.linkedUser(email, { roles: ['admin'] })
    const sibling = await h.signIn(email)
    await h.live().update({
      collection: 'ba-sessions',
      where: { token: { equals: h.rawTokenOf(cookie) } },
      data: { expiresAt: PAST },
      overrideAccess: true,
    })
    expect(await h.meId({ cookie })).toBeNull()
    expect((await h.accessOf({ cookie })).canAccessAdmin).toBeFalsy()
    expect((await h.accessOf({ cookie: sibling })).canAccessAdmin).toBe(true)
    const signOut = await h.baPost('/sign-out', {}, { cookie: sibling })
    expect(signOut.status).toBe(200)
    expect(await h.meId({ cookie: sibling })).toBeNull()
    expect((await h.accessOf({ cookie: sibling })).canAccessAdmin).toBeFalsy()
  })
})

describe('row 22: an operator-proven BA identity kills every pre-link local session', () => {
  it('two pre-link JWTs both die at the link; a fresh local login is refused', async () => {
    const email = 'two-devices@ba-rest.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    const laptop = h.jwtCookieOf(await h.localLogin(email))
    const phone = h.jwtCookieOf(await h.localLogin(email))
    expect(await h.readsDoc({ cookie: laptop }, id)).toBe(true)
    expect(await h.readsDoc({ cookie: phone }, id)).toBe(true)
    expect((await h.hostDoc(id)).sessions).toHaveLength(2)
    expect(await h.hostIdOf(await h.verifiedSession(email))).toBe(id)
    expect((await h.hostDoc(id)).sessions).toEqual([])
    expect(await h.readsDoc({ cookie: laptop }, id)).toBe(false)
    expect(await h.readsDoc({ cookie: phone }, id)).toBe(false)
    expect((await h.localLogin(email)).status).toBe(403)
  })

  it('failure: an unverified BA sign-in does not link, so the local JWT keeps working', async () => {
    const email = 'not-yet-linked@ba-rest.test'
    const id = await h.createDoc(email, { linkable: true, linkableEmail: email })
    const jwt = h.jwtCookieOf(await h.localLogin(email))
    const unverified = await h.signUp(email)
    expect((await h.pluginSession(unverified)).status).toBe(401)
    expect(h.identitiesOf(await h.hostDoc(id))).toEqual([])
    expect(await h.readsDoc({ cookie: jwt }, id)).toBe(true)
  })
})

describe('row 23: self-service email change on an unlinked document (real BA)', () => {
  it('the change clears the proof; the real owner is refused, never linked to the squatter', async () => {
    const squatter = 'squatter@ba-rest.test'
    const victim = 'squat-victim@ba-rest.test'
    const id = await h.createDoc(squatter, { linkable: true, linkableEmail: squatter })
    const jwt = h.jwtCookieOf(await h.localLogin(squatter))
    const moved = await h.rest('PATCH', `/users/${id}`, { cookie: jwt, body: { email: victim } })
    expect(moved.status).toBe(200)
    const doc = await h.hostDoc(id)
    expect(doc.email).toBe(victim)
    expect(doc.linkable).toBe(false)
    expect(doc.linkableEmail ?? null).toBeNull()
    // The real owner of the address proves it to BA — and is refused
    // (typed 401), never linked to the squatter's document.
    const owner = await h.verifiedSession(victim)
    expect((await h.pluginSession(owner)).status).toBe(401)
    expect(h.identitiesOf(await h.hostDoc(id))).toEqual([])
  })

  it("a role manager's email change: the proof stays bound to the OLD address until re-granted", async () => {
    const before = 'manager-moved-before@ba-rest.test'
    const after = 'manager-moved-after@ba-rest.test'
    const id = await h.createDoc(before, { linkable: true, linkableEmail: before })
    await h.createDoc('row23-manager@ba-rest.test', { roles: ['admin'] })
    const manager = h.jwtCookieOf(await h.localLogin('row23-manager@ba-rest.test'))
    const moved = await h.rest('PATCH', `/users/${id}`, {
      cookie: manager,
      body: { email: after },
    })
    expect(moved.status).toBe(200)
    expect((await h.hostDoc(id)).linkableEmail).toBe(before)
    // Failure: the bound proof does not cover the new address.
    const owner = await h.verifiedSession(after)
    expect((await h.pluginSession(owner)).status).toBe(401)
    expect(h.identitiesOf(await h.hostDoc(id))).toEqual([])
    // Success: the manager re-grants the proof for the new address.
    const regranted = await h.rest('PATCH', `/users/${id}`, {
      cookie: manager,
      body: { linkable: true, linkableEmail: after },
    })
    expect(regranted.status).toBe(200)
    expect(await h.hostIdOf(await h.signIn(after))).toBe(id)
  })
})

describe('rows 24 + 25: organizations under BA sessions', () => {
  let owner = ''
  let member = ''
  let orgId = ''

  beforeAll(async () => {
    owner = await h.verifiedSession('org-owner@ba-rest.test')
    member = await h.verifiedSession('org-member@ba-rest.test')
    await h.hostIdOf(owner)
    await h.hostIdOf(member)
  })

  it('row 24: create needs CSRF proof and a live session', async () => {
    const body = { name: 'BA Paths Org', slug: 'ba-paths-org' }
    expect(
      (await h.rest('POST', '/auth-link/organizations', { cookie: owner, body, csrf: false }))
        .status
    ).toBe(403)
    expect((await h.rest('POST', '/auth-link/organizations', { body })).status).toBe(401)
    const created = await h.rest('POST', '/auth-link/organizations', { cookie: owner, body })
    expect(created.status).toBe(201)
    orgId = (created.body as { organization: { id: string } }).organization.id
  })

  it('row 24: an expired or suspended session cannot create', async () => {
    const email = 'org-expired@ba-rest.test'
    const { id, cookie } = await h.linkedUser(email)
    const fresh = await h.signIn(email)
    await h.live().update({
      collection: 'ba-sessions',
      where: { token: { equals: h.rawTokenOf(cookie) } },
      data: { expiresAt: PAST },
      overrideAccess: true,
    })
    const body = { name: 'Expired Org', slug: 'ba-expired-org' }
    expect((await h.rest('POST', '/auth-link/organizations', { cookie, body })).status).toBe(401)
    await h.suspend(id)
    expect((await h.rest('POST', '/auth-link/organizations', { cookie: fresh, body })).status).toBe(
      401
    )
  })

  it('row 24: invite is manager-only; accept is the invited address only', async () => {
    const added = await h.rest('POST', '/auth-link/organizations/invite', {
      cookie: owner,
      body: { organizationId: orgId, email: 'org-member@ba-rest.test', role: 'member' },
    })
    expect(added.status).toBe(201)
    const noCsrf = await h.rest('POST', '/auth-link/organizations/invite', {
      cookie: owner,
      csrf: false,
      body: { organizationId: orgId, email: 'org-nocsrf@ba-rest.test', role: 'member' },
    })
    expect(noCsrf.status).toBe(403)
    const byMember = await h.rest('POST', '/auth-link/organizations/invite', {
      cookie: member,
      body: { organizationId: orgId, email: 'org-other@ba-rest.test', role: 'member' },
    })
    expect(byMember.status).toBe(403)
    const pending = await h.rest('POST', '/auth-link/organizations/invite', {
      cookie: owner,
      body: { organizationId: orgId, email: 'org-future@ba-rest.test', role: 'member' },
    })
    expect(pending.status).toBe(201)
    const invitationId = (pending.body as { invitation: { id: string } }).invitation.id
    const stolen = await h.rest('POST', '/auth-link/organizations/accept', {
      cookie: member,
      body: { invitationId },
    })
    expect(stolen.status).toBe(403)
    // The invited address, unproven at BA: no session, no accept.
    const unproven = await h.signUp('org-future@ba-rest.test')
    expect(
      (
        await h.rest('POST', '/auth-link/organizations/accept', {
          cookie: unproven,
          body: { invitationId },
        })
      ).status
    ).toBe(401)
    await h.markBaVerified('org-future@ba-rest.test')
    const future = await h.signIn('org-future@ba-rest.test')
    const accepted = await h.rest('POST', '/auth-link/organizations/accept', {
      cookie: future,
      body: { invitationId },
    })
    expect(accepted.status).toBe(200)
  })

  it('row 25: a plain member cannot escalate their own membership', async () => {
    const memberId = await h.hostIdOf(member)
    const rows = await h.live().find({
      collection: 'memberships',
      where: { and: [{ user: { equals: memberId } }, { organization: { equals: orgId } }] },
      overrideAccess: true,
    })
    const row = rows.docs[0]
    if (row === undefined) {
      throw new Error('membership row missing')
    }
    const attempt = await h.rest('PATCH', `/memberships/${String(row.id)}`, {
      cookie: member,
      body: { role: 'owner' },
    })
    expect(attempt.status).toBe(403)
    expect(
      (await h.live().findByID({ collection: 'memberships', id: row.id, overrideAccess: true }))
        .role
    ).toBe('member')
    expect((await h.rest('GET', '/memberships')).status).toBe(403)
  })

  it('row 25: the owner manages the membership; the last owner cannot be removed', async () => {
    const memberId = await h.hostIdOf(member)
    const ownerId = await h.hostIdOf(owner)
    const rowOf = async (userId: string) => {
      const rows = await h.live().find({
        collection: 'memberships',
        where: { and: [{ user: { equals: userId } }, { organization: { equals: orgId } }] },
        overrideAccess: true,
      })
      const row = rows.docs[0]
      if (row === undefined) {
        throw new Error('membership row missing')
      }
      return String(row.id)
    }
    const promoted = await h.rest('PATCH', `/memberships/${await rowOf(memberId)}`, {
      cookie: owner,
      body: { role: 'admin' },
    })
    expect(promoted.status).toBe(200)
    const lastOwner = await h.rest('DELETE', `/memberships/${await rowOf(ownerId)}`, {
      cookie: owner,
    })
    expect(lastOwner.status).toBe(409)
  })
})

describe('row 26: the server-side session verifier over a BA session', () => {
  const verifier = createSessionVerifier({
    baseUrl: ORIGIN,
    fetchImpl: (input, init) =>
      handleEndpoints({ config: h.config(), request: new Request(input, init) }),
  })

  it('success: the forwarded BA cookie verifies to its user; failure: forged / expired / suspended → null', async () => {
    const email = 'verifier@ba-rest.test'
    const { id, cookie } = await h.linkedUser(email)
    const user = await verifier(new Headers({ cookie }))
    expect(user?.id).toBe(id)
    expect(
      await verifier(new Headers({ cookie: `${h.sessionCookieName}=forged.signature` }))
    ).toBeNull()
    expect(await verifier(new Headers())).toBeNull()
    const sibling = await h.signIn(email)
    await h.live().update({
      collection: 'ba-sessions',
      where: { token: { equals: h.rawTokenOf(sibling) } },
      data: { expiresAt: PAST },
      overrideAccess: true,
    })
    expect(await verifier(new Headers({ cookie: sibling }))).toBeNull()
    await h.suspend(id)
    expect(await verifier(new Headers({ cookie }))).toBeNull()
  })

  it('failure: construction without baseUrl outside development throws', () => {
    expect(() => createSessionVerifier({ environment: { nodeEnv: 'production' } })).toThrow(
      /requires baseUrl/
    )
  })
})

describe('row 27: users writes by other signed-in BA users', () => {
  it("a user may update their own document but not another user's", async () => {
    const alice = await h.linkedUser('row27-alice@ba-rest.test')
    const bob = await h.linkedUser('row27-bob@ba-rest.test')
    expect(
      (await h.rest('PATCH', `/users/${alice.id}`, { cookie: alice.cookie, body: {} })).status
    ).toBe(200)
    const other = await h.rest('PATCH', `/users/${bob.id}`, {
      cookie: alice.cookie,
      body: { email: 'hijacked@ba-rest.test' },
    })
    expect([403, 404]).toContain(other.status)
    expect((await h.hostDoc(bob.id)).email).toBe('row27-bob@ba-rest.test')
    const removed = await h.rest('DELETE', `/users/${bob.id}`, { cookie: alice.cookie })
    expect([403, 404]).toContain(removed.status)
    expect((await h.hostDoc(bob.id)).id).toBeDefined()
    const unlock = await h.rest('POST', '/users/unlock', {
      cookie: alice.cookie,
      body: { email: 'row27-bob@ba-rest.test' },
    })
    expect(unlock.status).toBe(403)
  })

  it('failure: a role write is refused for a non-manager; a manager may update others', async () => {
    const carol = await h.linkedUser('row27-carol@ba-rest.test')
    const escalate = await h.rest('PATCH', `/users/${carol.id}`, {
      cookie: carol.cookie,
      body: { roles: ['admin'] },
    })
    expect((await h.hostDoc(carol.id)).roles).toEqual(['user'])
    expect([200, 403]).toContain(escalate.status)
    const admin = await h.linkedUser('row27-admin@ba-rest.test', { roles: ['admin'] })
    const managed = await h.rest('PATCH', `/users/${carol.id}`, {
      cookie: admin.cookie,
      body: { roles: ['admin'] },
    })
    expect(managed.status).toBe(200)
    expect((await h.hostDoc(carol.id)).roles).toEqual(['admin'])
  })

  it('failure: a suspended user cannot update even their own document', async () => {
    const dave = await h.linkedUser('row27-dave@ba-rest.test')
    await h.suspend(dave.id)
    const own = await h.rest('PATCH', `/users/${dave.id}`, { cookie: dave.cookie, body: {} })
    expect([401, 403]).toContain(own.status)
  })
})
