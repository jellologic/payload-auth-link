/**
 * The credential-path matrix (docs/security-model.md) walked on a REAL
 * Auth.js engine (issue #84 §1): real `@auth/core` 0.41 with database
 * sessions and an email (magic-link) provider, on real Payload storage
 * (SQLite in memory), behind a real authLink boot. Sessions are minted
 * by Auth.js's own sign-in and callback actions, never by a stub.
 *
 * Every applicable row is walked with its success path AND its
 * failure paths: a wrong / expired magic-link token, an expired or
 * revoked session, another user's credential, a suspended user, and an
 * unproven email. Rows that do not apply to Auth.js are pinned as
 * such (the engine honestly lacks the primitive):
 *
 * - row 2: Auth.js resolves sessions from cookies only (no bearer
 *   transport) — a bearer-presented session token authenticates
 *   nothing;
 * - row 14: Auth.js has no change-password / reset-password endpoint;
 *   the provider-side change is the adapter's own `updateUser`
 *   (builder flows), and only a provider-VERIFIED address resyncs;
 * - row 15: Auth.js has no impersonation primitive — the capability is
 *   never declared, so no session ever carries an actor;
 * - MFA policy: Auth.js declares no `mfa` capability, so a
 *   `requireMfaForRoles` policy fails at wiring (D4).
 *
 * One Payload instance per file (getPayload caches per process): the
 * FIRST write on the empty database is Payload's `first-register`
 * (row 13), so `beforeAll` order matters.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink, authLinkServer, ServerSessionUnsupportedError } from '@payload-auth-link/plugin'
import { createSessionVerifier } from '@payload-auth-link/web'
import type { AuthConfig } from '@auth/core'
import type { AdapterUser } from '@auth/core/adapters'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAuthJsEngine } from '../engine.js'

const ORIGIN = 'http://credential-paths-authjs.test'
const SECRET = 'credential-paths-authjs-engine-secret!!'
const BASE_PATH = '/api/authjs'
const PASSWORD = 'correct-horse-battery'
const SUSPENDED_UNTIL = '2031-01-01T00:00:00.000Z'
const PAST = '2020-01-01T00:00:00.000Z'
const FOUNDER = 'founder@authjs-paths.test'

/** Outbox: the last magic-link URL Auth.js sent per address. */
const outbox = new Map<string, string>()

const magicLink: AuthConfig['providers'][number] = {
  id: 'magic',
  type: 'email',
  name: 'Magic link',
  maxAge: 600,
  sendVerificationRequest: ({ identifier, url }) => {
    outbox.set(identifier, url)
  },
}

let config: SanitizedConfig
let payload: Payload | undefined

const engine = createAuthJsEngine({
  getPayload: () => {
    if (!payload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(payload)
  },
  baseURL: ORIGIN,
  options: {
    basePath: BASE_PATH,
    secret: SECRET,
    session: { strategy: 'database' },
    providers: [magicLink],
  },
})

const pluginOptions = {
  baseUrl: ORIGIN,
  roles: ['admin', 'user'],
  defaultRole: 'user',
  providers: [engine.provider],
  organizations: { enabled: true },
  allowServerSessions: true,
} as const

function live(): Payload {
  if (!payload) {
    throw new Error('Payload not ready')
  }
  return payload
}

/** Pages with this title, read past access control: proves a refused write wrote nothing. */
async function pagesTitled(title: string): Promise<number> {
  const { totalDocs } = await live().count({
    collection: 'pages',
    where: { title: { equals: title } },
    overrideAccess: true,
  })
  return totalDocs
}

class Jar {
  private pairs = new Map<string, string>()

  store(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(';')
      const separator = pair?.indexOf('=') ?? -1
      if (pair === undefined || separator <= 0) {
        continue
      }
      const name = pair.slice(0, separator).trim()
      const value = pair.slice(separator + 1).trim()
      if (value === '') {
        this.pairs.delete(name)
      } else {
        this.pairs.set(name, value)
      }
    }
  }

  get(name: string): string | undefined {
    return this.pairs.get(name)
  }

  header(): string {
    return [...this.pairs.entries()].map(([name, value]) => `${name}=${value}`).join('; ')
  }
}

const sessionCookieName = engine.sessionCookieNames[0] ?? ''

/** Ask Auth.js for a magic link (its CSRF-protected sign-in action). */
async function requestLink(email: string): Promise<{ jar: Jar; url: string }> {
  const jar = new Jar()
  outbox.delete(email)
  const csrf = await engine.handleRequest(new Request(`${ORIGIN}${BASE_PATH}/csrf`))
  jar.store(csrf)
  const { csrfToken } = (await csrf.json()) as { csrfToken?: unknown }
  if (typeof csrfToken !== 'string') {
    throw new Error('csrf action returned no token')
  }
  const signIn = await engine.handleRequest(
    new Request(`${ORIGIN}${BASE_PATH}/signin/magic`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
      body: new URLSearchParams({ csrfToken, email, callbackUrl: `${ORIGIN}/account` }),
      redirect: 'manual',
    })
  )
  jar.store(signIn)
  const url = outbox.get(email)
  if (url === undefined) {
    throw new Error(`no magic link sent (status ${String(signIn.status)})`)
  }
  return { jar, url }
}

/** Follow a magic-link URL through Auth.js's callback action. */
async function follow(jar: Jar, url: string): Promise<{ jar: Jar; location: string }> {
  const target = new URL(url)
  const done = await engine.handleRequest(
    new Request(`${ORIGIN}${target.pathname}${target.search}`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    })
  )
  jar.store(done)
  return { jar, location: done.headers.get('location') ?? '' }
}

/** A full Auth.js magic-link sign-in; returns the session cookie pair. */
async function signIn(email: string): Promise<string> {
  const { jar, url } = await requestLink(email)
  const { location } = await follow(jar, url)
  expect(location).not.toContain('error=')
  const token = jar.get(sessionCookieName)
  if (token === undefined) {
    throw new Error('Auth.js set no session cookie')
  }
  return `${sessionCookieName}=${token}`
}

function tokenOf(cookie: string): string {
  return cookie.slice(cookie.indexOf('=') + 1)
}

type Reply = { status: number; body: unknown; headers: Headers }

async function rest(
  method: string,
  path: string,
  opts: { cookie?: string; body?: unknown; csrf?: boolean; authorization?: string } = {}
): Promise<Reply> {
  const headers: Record<string, string> = {}
  if (opts.csrf !== false) {
    headers.origin = ORIGIN
  }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.authorization !== undefined) {
    headers.authorization = opts.authorization
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body, headers: response.headers }
}

function pluginSession(cookie: string): Promise<Reply> {
  return rest('GET', '/auth-link/session', { cookie })
}

async function hostIdOf(cookie: string): Promise<string> {
  const reply = await pluginSession(cookie)
  expect(reply.status).toBe(200)
  const id = (reply.body as { user?: { id?: unknown } }).user?.id
  if (typeof id !== 'string' && typeof id !== 'number') {
    throw new Error('the bridge resolved no user')
  }
  return String(id)
}

async function hostDoc(id: string | number): Promise<Record<string, unknown>> {
  return live().findByID({
    collection: 'users',
    id,
    depth: 0,
    overrideAccess: true,
    showHiddenFields: true,
  })
}

async function hostDocByEmail(email: string): Promise<Record<string, unknown> | undefined> {
  const found = await live().find({
    collection: 'users',
    where: { email: { equals: email } },
    limit: 1,
    depth: 0,
    overrideAccess: true,
    showHiddenFields: true,
  })
  return found.docs[0]
}

function identitiesOf(doc: Record<string, unknown> | undefined): unknown[] {
  const identities = doc?.identities
  return Array.isArray(identities) ? identities : []
}

/** A host document created outside the plugin (Local API, no marker). */
async function createDoc(email: string, data: Record<string, unknown> = {}): Promise<string> {
  const created = await live().create({
    collection: 'users',
    data: { email, password: PASSWORD, roles: ['user'], _verified: true, ...data },
    overrideAccess: true,
    disableVerificationEmail: true,
  })
  return String(created.id)
}

/** The role manager's proof grant (the runbook's manager action). */
async function grantProof(id: string, email: string): Promise<void> {
  await live().update({
    collection: 'users',
    id,
    data: { linkable: true, linkableEmail: email },
    overrideAccess: true,
  })
}

async function suspend(id: string, until: string | null = SUSPENDED_UNTIL): Promise<void> {
  await live().update({
    collection: 'users',
    id,
    data: { suspendedUntil: until },
    overrideAccess: true,
  })
}

/** A proven host document linked through a real Auth.js sign-in. */
async function linkedUser(
  email: string,
  data: Record<string, unknown> = {}
): Promise<{ id: string; cookie: string }> {
  const id = await createDoc(email, { linkable: true, linkableEmail: email, ...data })
  const cookie = await signIn(email)
  expect(await hostIdOf(cookie)).toBe(id)
  return { id, cookie }
}

async function localLogin(email: string, password = PASSWORD): Promise<Reply> {
  return rest('POST', '/users/login', { body: { email, password } })
}

function jwtCookieOf(reply: Reply): string {
  const cookie = (reply.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
  expect(cookie).toMatch(/^payload-token=./)
  return cookie
}

async function accessOf(cookie: string): Promise<{ canAccessAdmin: unknown }> {
  const access = await rest('GET', '/access', { cookie })
  expect(access.status).toBe(200)
  return { canAccessAdmin: (access.body as { canAccessAdmin?: unknown }).canAccessAdmin }
}

async function meId(opts: { cookie?: string; authorization?: string }): Promise<string | null> {
  const me = await rest('GET', '/users/me', opts)
  const user = (me.body as { user?: { id?: unknown } | null } | null)?.user
  return user === null || user === undefined ? null : String(user.id)
}

let founderId = ''

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      // Payload email verification (row 8) and a host-enabled API key
      // channel (row 10): every credential surface the matrix names.
      { slug: 'users', auth: { verify: true, useAPIKey: true }, fields: [] },
      { slug: 'pages', fields: [{ name: 'title', type: 'text', required: true }] },
      ...engine.collections,
    ],
    plugins: [authLink(pluginOptions)],
  })
  payload = await getPayload({ config })
  // Row 13: the very first write on the empty database.
  const registered = await rest('POST', '/users/first-register', {
    body: { email: FOUNDER, password: PASSWORD, 'confirm-password': PASSWORD },
  })
  expect(registered.status).toBe(200)
  const id = (registered.body as { user?: { id?: unknown } }).user?.id
  if (typeof id !== 'string' && typeof id !== 'number') {
    throw new Error('first-register returned no user')
  }
  founderId = String(id)
}, 120_000)

describe('row 13: first-register on an empty DB (real Auth.js)', () => {
  it('starts unproven, and a verified Auth.js identity is NOT JIT-linked to it', async () => {
    expect((await hostDoc(founderId)).linkable).toBe(false)
    const cookie = await signIn(FOUNDER)
    expect((await pluginSession(cookie)).status).toBe(401)
    expect(identitiesOf(await hostDoc(founderId))).toEqual([])
  })

  it('a second first-register is refused once a user exists', async () => {
    const again = await rest('POST', '/users/first-register', {
      body: { email: 'second@authjs-paths.test', password: PASSWORD, 'confirm-password': PASSWORD },
    })
    expect(again.status).toBe(403)
  })

  it('success: after a manager grants the proof, the same identity links', async () => {
    await grantProof(founderId, FOUNDER)
    expect(await hostIdOf(await signIn(FOUNDER))).toBe(founderId)
  })
})

describe('row 1: the auth-link session cookie (real Auth.js)', () => {
  it('success: a verified magic-link sign-in provisions and links a new user', async () => {
    const email = 'fresh@authjs-paths.test'
    const cookie = await signIn(email)
    const id = await hostIdOf(cookie)
    const doc = await hostDoc(id)
    expect(doc.email).toBe(email)
    expect(identitiesOf(doc)).toEqual([expect.objectContaining({ providerId: 'authjs' })])
  })

  it('failure: a wrong magic-link token mints no session', async () => {
    const email = 'wrong-token@authjs-paths.test'
    const { jar, url } = await requestLink(email)
    const forged = new URL(url)
    forged.searchParams.set('token', 'not-the-token')
    const { location } = await follow(jar, forged.toString())
    expect(location).toContain('error=Verification')
    expect(jar.get(sessionCookieName)).toBeUndefined()
    expect(await hostDocByEmail(email)).toBeUndefined()
  })

  it('failure: an expired magic-link token mints no session', async () => {
    const email = 'expired-link@authjs-paths.test'
    const { jar, url } = await requestLink(email)
    await live().update({
      collection: 'aj-verification-tokens',
      where: { identifier: { equals: email } },
      data: { expires: PAST },
      overrideAccess: true,
    })
    const { location } = await follow(jar, url)
    expect(location).toContain('error=Verification')
    expect(jar.get(sessionCookieName)).toBeUndefined()
  })

  it("failure: another address's magic link cannot be redeemed for this address", async () => {
    const victim = 'link-victim@authjs-paths.test'
    const attacker = 'link-attacker@authjs-paths.test'
    const { url } = await requestLink(victim)
    const { jar } = await requestLink(attacker)
    const swapped = new URL(url)
    swapped.searchParams.set('email', attacker)
    const { location } = await follow(jar, swapped.toString())
    expect(location).toContain('error=Verification')
    expect(jar.get(sessionCookieName)).toBeUndefined()
  })

  it('failure: an expired database session is refused', async () => {
    const cookie = await signIn('expired-session@authjs-paths.test')
    await hostIdOf(cookie)
    await live().update({
      collection: 'aj-sessions',
      where: { sessionToken: { equals: tokenOf(cookie) } },
      data: { expires: PAST },
      overrideAccess: true,
    })
    expect((await pluginSession(cookie)).status).toBe(401)
  })

  it('failure: a forged session token is refused; each cookie resolves only its own user', async () => {
    expect((await pluginSession(`${sessionCookieName}=forged-session-token`)).status).toBe(401)
    const alice = await signIn('alice@authjs-paths.test')
    const bob = await signIn('bob@authjs-paths.test')
    expect(await hostIdOf(alice)).not.toBe(await hostIdOf(bob))
  })

  it('failure: an unproven (unverified) Auth.js email never provisions or links', async () => {
    const email = 'unverified@authjs-paths.test'
    const adapter = engine.config.adapter
    if (adapter?.createUser === undefined || adapter.createSession === undefined) {
      throw new Error('engine adapter is missing user/session methods')
    }
    // What an OAuth provider outside the trust allow-list leaves behind
    // (see oauth.test.ts): an adapter user with emailVerified null.
    const proven = await createDoc(email, { linkable: true, linkableEmail: email })
    const user: AdapterUser = await adapter.createUser({ id: '', email, emailVerified: null })
    await adapter.createSession({
      sessionToken: 'unverified-session-token',
      userId: user.id,
      expires: new Date(Date.now() + 3600_000),
    })
    const reply = await pluginSession(`${sessionCookieName}=unverified-session-token`)
    expect(reply.status).toBe(401)
    expect(identitiesOf(await hostDoc(proven))).toEqual([])
  })

  it('failure: an unproven pre-existing document is never JIT-linked (findByEmail gate)', async () => {
    const email = 'unproven-doc@authjs-paths.test'
    const id = await createDoc(email)
    expect((await pluginSession(await signIn(email))).status).toBe(401)
    expect(identitiesOf(await hostDoc(id))).toEqual([])
  })

  it('failure: a suspended user is refused on the next request and the sessions are revoked', async () => {
    const { id, cookie } = await linkedUser('suspended-cookie@authjs-paths.test')
    await suspend(id)
    expect((await pluginSession(cookie)).status).toBe(401)
    expect((await pluginSession(await signIn('suspended-cookie@authjs-paths.test'))).status).toBe(
      401
    )
    // The dead cookie authenticates nothing, so the request is anonymous:
    // Payload's default create access refuses it with 403 (never 401).
    const attempt = await rest('POST', '/pages', { cookie, body: { title: 'suspended-write' } })
    expect(attempt.status).toBe(403)
    expect(await pagesTitled('suspended-write')).toBe(0)
    await suspend(id, null)
    expect(await hostIdOf(await signIn('suspended-cookie@authjs-paths.test'))).toBe(id)
  })

  it('MFA policy: n/a — Auth.js declares no mfa capability, so the policy fails at wiring', () => {
    expect(engine.provider.capabilities.has('mfa')).toBe(false)
    expect(() =>
      authLink({ ...pluginOptions, policies: { requireMfaForRoles: ['admin'] } })
    ).toThrow(/mfa/)
  })
})

describe('row 2: bearer / api-key channel — n/a on Auth.js (cookie-only engine)', () => {
  it('a bearer-presented Auth.js session token authenticates nothing', async () => {
    const cookie = await signIn('bearer@authjs-paths.test')
    await hostIdOf(cookie)
    const bearer = { authorization: `Bearer ${tokenOf(cookie)}` }
    expect((await rest('GET', '/auth-link/session', bearer)).status).toBe(401)
    expect(await meId(bearer)).toBeNull()
  })
})

describe('rows 3–7 and 22: local credentials on an Auth.js-linked document', () => {
  const email = 'provider-owned@authjs-paths.test'
  const operator = 'operator@authjs-paths.test'
  let id = ''
  let preLinkJwt = ''

  beforeAll(async () => {
    id = await createDoc(email, { linkable: true, linkableEmail: email })
    // Row 22: a local JWT minted while the document was still unlinked.
    const login = await localLogin(email)
    expect(login.status).toBe(200)
    preLinkJwt = jwtCookieOf(login)
    expect(await meId({ cookie: preLinkJwt })).toBe(id)
    expect(await hostIdOf(await signIn(email))).toBe(id)
    await createDoc(operator, { roles: ['admin'] })
    await live().update({
      collection: 'users',
      id,
      data: { resetPasswordToken: 'linked-reset-token', resetPasswordExpiration: SUSPENDED_UNTIL },
      overrideAccess: true,
    })
  })

  it('row 22: the pre-link local JWT is dead after the Auth.js link', async () => {
    expect(await meId({ cookie: preLinkJwt })).toBeNull()
    // Anonymous after the link: default create access answers 403.
    const write = await rest('POST', '/pages', {
      cookie: preLinkJwt,
      body: { title: 'pre-link-jwt-write' },
    })
    expect(write.status).toBe(403)
    expect(await pagesTitled('pre-link-jwt-write')).toBe(0)
  })

  it('row 3: local login is refused (403) on the linked document; an operator keeps it', async () => {
    expect((await localLogin(email)).status).toBe(403)
    expect((await localLogin(operator)).status).toBe(200)
    expect((await localLogin(operator, 'wrong-password-1')).status).toBe(401)
  })

  it('rows 4 + 5: an operator JWT works and refreshes; the pre-link JWT cannot refresh', async () => {
    const jwt = jwtCookieOf(await localLogin(operator))
    expect((await rest('POST', '/pages', { cookie: jwt, body: { title: 'ok' } })).status).toBe(201)
    expect((await rest('POST', '/users/refresh-token', { cookie: jwt, body: {} })).status).toBe(200)
    const refreshed = await rest('POST', '/users/refresh-token', { cookie: preLinkJwt, body: {} })
    expect(refreshed.status).toBe(403)
  })

  it('rows 4 + 5: a suspended local JWT is refused on the next request and cannot refresh', async () => {
    const local = 'suspended-local@authjs-paths.test'
    const localId = await createDoc(local)
    const jwt = jwtCookieOf(await localLogin(local))
    await suspend(localId)
    // The JWT resolves no user at authentication (GHSA-mjvh): anonymous.
    expect((await rest('POST', '/pages', { cookie: jwt, body: { title: 'x' } })).status).toBe(403)
    expect((await rest('POST', '/users/refresh-token', { cookie: jwt, body: {} })).status).toBe(403)
    expect((await localLogin(local)).status).toBe(401)
  })

  it('row 6: forgot-password is refused (403) on the linked document, allowed for the operator', async () => {
    expect((await rest('POST', '/users/forgot-password', { body: { email } })).status).toBe(403)
    expect(
      (await rest('POST', '/users/forgot-password', { body: { email: operator } })).status
    ).toBe(200)
  })

  it('row 7: a reset token minted before linking dies (403); the password never rotates', async () => {
    const reset = await rest('POST', '/users/reset-password', {
      body: { token: 'linked-reset-token', password: 'RotatedByReset-1' },
    })
    expect(reset.status).toBe(403)
    expect((await localLogin(email, 'RotatedByReset-1')).status).toBe(401)
    const wrong = await rest('POST', '/users/reset-password', {
      body: { token: 'no-such-token', password: 'RotatedByReset-1' },
    })
    expect(wrong.status).toBe(403)
  })
})

describe("row 8: Payload's verify token is not linkable proof on its own (real Auth.js)", () => {
  const email = 'verify-only@authjs-paths.test'
  let id = ''

  beforeAll(async () => {
    id = await createDoc(email, { _verified: false })
  })

  it('failure: a wrong verification token verifies nothing', async () => {
    // Payload answers an unknown verification token with Forbidden.
    expect((await rest('POST', '/users/verify/not-the-token')).status).toBe(403)
    expect((await hostDoc(id))._verified).toBe(false)
  })

  it('success: the right token verifies and mints no session', async () => {
    const token = (await hostDoc(id))._verificationToken
    expect(typeof token).toBe('string')
    const verified = await rest('POST', `/users/verify/${String(token)}`)
    expect(verified.status).toBe(200)
    expect(verified.headers.get('set-cookie')).toBeNull()
  })

  it('failure: `_verified` alone never admits the Auth.js identity', async () => {
    expect((await pluginSession(await signIn(email))).status).toBe(401)
    expect(identitiesOf(await hostDoc(id))).toEqual([])
  })

  it('success: `_verified` WITH the manager proof links', async () => {
    await grantProof(id, email)
    expect(await hostIdOf(await signIn(email))).toBe(id)
  })
})

describe('row 10: useAPIKey (real Auth.js)', () => {
  it('an existing key on an unlinked document works until the user is suspended, then anonymous', async () => {
    const id = await createDoc('api-key@authjs-paths.test')
    const key = 'authjs-unlinked-api-key-0123456789abcdef'
    await live().update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: key },
      overrideAccess: true,
    })
    const authorization = `users API-Key ${key}`
    expect(await meId({ authorization })).toBe(id)
    expect((await rest('POST', '/pages', { authorization, body: { title: 'k' } })).status).toBe(201)
    await suspend(id)
    // The key resolves no user at authentication (GHSA-mjvh): anonymous.
    expect(await meId({ authorization })).toBeNull()
    expect((await rest('POST', '/pages', { authorization, body: { title: 'k' } })).status).toBe(403)
    expect((await rest('PATCH', `/users/${id}`, { authorization, body: {} })).status).toBe(403)
    expect(await meId({ authorization: 'users API-Key not-a-real-key' })).toBeNull()
  })

  it('row 10a: a key on an Auth.js-linked document is refused (403)', async () => {
    const { id } = await linkedUser('api-key-linked@authjs-paths.test')
    const key = 'authjs-linked-api-key-0123456789abcdef'
    await live().update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: key },
      overrideAccess: true,
    })
    const authorization = `users API-Key ${key}`
    expect(await meId({ authorization })).toBeNull()
    expect((await rest('GET', `/users/${id}`, { authorization })).status).toBe(403)
    expect((await rest('PATCH', `/users/${id}`, { authorization, body: {} })).status).toBe(403)
    expect((await rest('POST', '/pages', { authorization, body: { title: 'k' } })).status).toBe(403)
  })
})

describe('row 12: Local API with overrideAccess still runs the hooks (real Auth.js)', () => {
  const email = 'local-api-linked@authjs-paths.test'
  let id = ''

  beforeAll(async () => {
    id = (await linkedUser(email)).id
    await live().update({
      collection: 'users',
      id,
      data: { resetPasswordToken: 'local-api-reset', resetPasswordExpiration: SUSPENDED_UNTIL },
      overrideAccess: true,
    })
  })

  it('failure: Local API login / forgot / reset on the Auth.js-linked document are refused', async () => {
    await expect(
      live().login({ collection: 'users', data: { email, password: PASSWORD } })
    ).rejects.toThrow()
    await expect(live().forgotPassword({ collection: 'users', data: { email } })).rejects.toThrow(
      /provider-linked/
    )
    await expect(
      live().resetPassword({
        collection: 'users',
        data: { token: 'local-api-reset', password: 'RotatedLocal-1' },
        overrideAccess: true,
      })
    ).rejects.toThrow()
  })

  it('success / failure: an operator Local API call works until the operator is suspended', async () => {
    const operatorId = await createDoc('local-api-operator@authjs-paths.test', { roles: ['admin'] })
    const asOperator = async (): Promise<unknown> =>
      live().find({
        collection: 'pages',
        user: { ...(await hostDoc(operatorId)), id: operatorId, collection: 'users' },
        overrideAccess: false,
      })
    await expect(asOperator()).resolves.toBeDefined()
    await suspend(operatorId)
    await expect(asOperator()).rejects.toThrow()
    // Engine paths carry no req.user: Auth.js still writes its own rows.
    const cookie = await signIn('local-api-operator@authjs-paths.test')
    expect(cookie).toContain(sessionCookieName)
  })
})

describe('row 14: provider-side changes on Auth.js (adapter updateUser; no password endpoints)', () => {
  const before = 'mover@authjs-paths.test'
  const after = 'moved@authjs-paths.test'
  let id = ''
  let cookie = ''

  async function adapterUserId(email: string): Promise<string> {
    const found = await live().find({
      collection: 'aj-users',
      where: { email: { equals: email } },
      limit: 1,
      overrideAccess: true,
    })
    const auId: unknown = found.docs[0]?.auId
    if (typeof auId !== 'string') {
      throw new Error(`no Auth.js user ${email}`)
    }
    return auId
  }

  /** The provider-side change: the Auth.js adapter's own updateUser. */
  async function updateAdapterUser(user: Partial<AdapterUser> & { id: string }): Promise<void> {
    const adapter = engine.config.adapter
    if (adapter?.updateUser === undefined) {
      throw new Error('engine adapter has no updateUser')
    }
    await adapter.updateUser(user)
  }

  beforeAll(async () => {
    ;({ id, cookie } = await linkedUser(before))
  })

  it('failure: an UNVERIFIED provider-side address change never resyncs', async () => {
    await updateAdapterUser({ id: await adapterUserId(before), email: after, emailVerified: null })
    // The linked session keeps working, under the last provider-VERIFIED
    // address: the unproven one never reaches Payload.
    const reply = await pluginSession(cookie)
    expect(reply.status).toBe(200)
    expect((reply.body as { user?: { email?: unknown } }).user?.email).toBe(before)
    const doc = await hostDoc(id)
    expect(doc.email).toBe(before)
    expect(doc.linkableEmail).toBe(before)
    expect(await hostDocByEmail(after)).toBeUndefined()
  })

  it('success: a provider-VERIFIED change moves the email and the linkable proof', async () => {
    await updateAdapterUser({
      id: await adapterUserId(after),
      email: after,
      emailVerified: new Date(),
    })
    expect(await hostIdOf(cookie)).toBe(id)
    const doc = await hostDoc(id)
    expect(doc.email).toBe(after)
    expect(doc.linkable).toBe(true)
    expect(doc.linkableEmail).toBe(after)
  })

  it('failure: suspension still refuses the session after the change', async () => {
    await suspend(id)
    expect((await pluginSession(cookie)).status).toBe(401)
    await suspend(id, null)
  })

  it('n/a: Auth.js exposes no change-password / reset-password endpoint', async () => {
    for (const action of ['change-password', 'reset-password', 'change-email']) {
      const response = await engine.handleRequest(
        new Request(`${ORIGIN}${BASE_PATH}/${action}`, { method: 'POST' })
      )
      // Auth.js rejects an action it does not define (UnknownAction).
      expect(response.status).toBe(400)
    }
  })
})

describe('row 15: impersonation — n/a on Auth.js', () => {
  it('no impersonation capability; a session never carries an actor', async () => {
    expect(engine.provider.capabilities.has('impersonation')).toBe(false)
    const cookie = await signIn('no-actor@authjs-paths.test')
    const session = (await engine.provider.getSession(new Headers({ cookie })))._unsafeUnwrap()
    expect(session?.actor).toBeNull()
  })
})

describe('row 16: /users/me and the /access map under an Auth.js session', () => {
  it('success: an admin session sees itself and the admin grant; suspended sees neither', async () => {
    const { id, cookie } = await linkedUser('admin-me@authjs-paths.test', { roles: ['admin'] })
    expect(await meId({ cookie })).toBe(id)
    expect((await accessOf(cookie)).canAccessAdmin).toBe(true)
    await suspend(id)
    expect(await meId({ cookie })).toBeNull()
    expect((await accessOf(cookie)).canAccessAdmin).toBeFalsy()
  })

  it('failure: a plain user holds no admin grant', async () => {
    const cookie = await signIn('plain-me@authjs-paths.test')
    expect(await meId({ cookie })).toEqual(expect.any(String))
    expect((await accessOf(cookie)).canAccessAdmin).toBeFalsy()
  })
})

describe('row 17: plugin session endpoints with an Auth.js session', () => {
  it('logout without CSRF proof is refused and the session survives', async () => {
    const cookie = await signIn('logout-csrf@authjs-paths.test')
    const refused = await rest('DELETE', '/auth-link/session', { cookie, csrf: false })
    expect(refused.status).toBe(403)
    await hostIdOf(cookie)
  })

  it('logout with CSRF proof deletes the database session row', async () => {
    const cookie = await signIn('logout@authjs-paths.test')
    await hostIdOf(cookie)
    const done = await rest('DELETE', '/auth-link/session', { cookie })
    expect(done.status).toBe(200)
    const rows = await live().find({
      collection: 'aj-sessions',
      where: { sessionToken: { equals: tokenOf(cookie) } },
      overrideAccess: true,
    })
    expect(rows.totalDocs).toBe(0)
    expect((await pluginSession(cookie)).status).toBe(401)
  })
})

/** The `aj-sessions` rows the Auth.js store holds for an address. */
async function storedSessionTokens(email: string): Promise<string[]> {
  const users = await live().find({
    collection: 'aj-users',
    where: { email: { equals: email } },
    limit: 1,
    overrideAccess: true,
  })
  const auId: unknown = users.docs[0]?.auId
  if (typeof auId !== 'string') {
    throw new Error(`no Auth.js user ${email}`)
  }
  const rows = await live().find({
    collection: 'aj-sessions',
    where: { userId: { equals: auId } },
    limit: 0,
    pagination: false,
    overrideAccess: true,
  })
  return rows.docs.map((row) => String(row.sessionToken)).sort()
}

describe('rows 18–20: server session API capability gates on Auth.js', () => {
  it('row 20: verifyApiKey is refused by capability (Auth.js has no API keys)', async () => {
    expect(engine.provider.capabilities.has('api-key-verify')).toBe(false)
    await expect(authLinkServer(live()).verifyApiKey('any-key')).rejects.toThrow(
      /capability api-key-verify/
    )
  })

  it('rows 18 + 18a: createSessionFor and listSessions are refused by capability — the store is untouched', async () => {
    const email = 'server-gates@authjs-paths.test'
    const { id, cookie } = await linkedUser(email)
    const before = await storedSessionTokens(email)
    expect(before).toEqual([tokenOf(cookie)])
    expect(engine.provider.capabilities.has('server-session-create')).toBe(false)
    expect(engine.provider.capabilities.has('server-session-list')).toBe(false)
    await expect(
      authLinkServer(live()).createSessionFor(id, { reason: 'gate-test' })
    ).rejects.toBeInstanceOf(ServerSessionUnsupportedError)
    await expect(authLinkServer(live()).listSessions(id)).rejects.toBeInstanceOf(
      ServerSessionUnsupportedError
    )
    // No row was minted (nor dropped) by the refused calls.
    expect(await storedSessionTokens(email)).toEqual(before)
  })

  it("row 19: revokeAllForUser deletes every row of one user and no one else's", async () => {
    const victimEmail = 'revoke-victim@authjs-paths.test'
    const bystanderEmail = 'revoke-bystander@authjs-paths.test'
    const victim = await linkedUser(victimEmail)
    const victimSecond = await signIn(victimEmail)
    const bystander = await linkedUser(bystanderEmail)
    expect(await storedSessionTokens(victimEmail)).toEqual(
      [tokenOf(victim.cookie), tokenOf(victimSecond)].sort()
    )
    const bystanderRows = await storedSessionTokens(bystanderEmail)
    expect(bystanderRows).toEqual([tokenOf(bystander.cookie)])
    await authLinkServer(live()).revokeAllForUser(victim.id)
    expect(await storedSessionTokens(victimEmail)).toEqual([])
    expect(await storedSessionTokens(bystanderEmail)).toEqual(bystanderRows)
    expect((await pluginSession(victim.cookie)).status).toBe(401)
    expect((await pluginSession(victimSecond)).status).toBe(401)
    expect(await hostIdOf(bystander.cookie)).toBe(bystander.id)
  })

  it('row 19: revokeAllForUser on a user with no linked identity is refused by capability', async () => {
    const unlinked = await createDoc('revoke-unlinked@authjs-paths.test')
    const total = (await live().count({ collection: 'aj-sessions', overrideAccess: true }))
      .totalDocs
    await expect(authLinkServer(live()).revokeAllForUser(unlinked)).rejects.toBeInstanceOf(
      ServerSessionUnsupportedError
    )
    expect(
      (await live().count({ collection: 'aj-sessions', overrideAccess: true })).totalDocs
    ).toBe(total)
  })

  // Found by this walk: the adapter's idempotent `deleteSession` made
  // an unknown handle read as revoked, and an Auth.js provider
  // registered first then ended the server API's walk over providers.
  it('row 19: revoking an unknown handle fails loudly and deletes nothing', async () => {
    const total = (await live().count({ collection: 'aj-sessions', overrideAccess: true }))
      .totalDocs
    await expect(authLinkServer(live()).revokeSession('no-such-session-token')).rejects.toThrow(
      /^revokeSession: /
    )
    expect(
      (await live().count({ collection: 'aj-sessions', overrideAccess: true })).totalDocs
    ).toBe(total)
  })

  it("row 19: revokeSession deletes exactly the presented handle's row", async () => {
    const email = 'revoke-one@authjs-paths.test'
    const { cookie: first } = await linkedUser(email)
    const second = await signIn(email)
    expect(await storedSessionTokens(email)).toEqual([tokenOf(first), tokenOf(second)].sort())
    await authLinkServer(live()).revokeSession(tokenOf(first))
    expect(await storedSessionTokens(email)).toEqual([tokenOf(second)])
    expect((await pluginSession(first)).status).toBe(401)
    await hostIdOf(second)
  })
})

describe('row 23: self-service email change on an unlinked document (real Auth.js)', () => {
  it('the change clears the proof; the real owner is refused, never linked to the squatter', async () => {
    const squatter = 'squatter@authjs-paths.test'
    const victim = 'squat-victim@authjs-paths.test'
    const id = await createDoc(squatter, { linkable: true, linkableEmail: squatter })
    const jwt = jwtCookieOf(await localLogin(squatter))
    const moved = await rest('PATCH', `/users/${id}`, { cookie: jwt, body: { email: victim } })
    expect(moved.status).toBe(200)
    const doc = await hostDoc(id)
    expect(doc.linkable).toBe(false)
    expect(doc._verified).toBe(false)
    expect((await pluginSession(await signIn(victim))).status).toBe(401)
    expect(identitiesOf(await hostDoc(id))).toEqual([])
  })
})

describe('rows 24 + 25: organizations under Auth.js sessions', () => {
  let owner = ''
  let member = ''
  let orgId = ''

  beforeAll(async () => {
    owner = await signIn('org-owner@authjs-paths.test')
    member = await signIn('org-member@authjs-paths.test')
    await hostIdOf(owner)
    await hostIdOf(member)
  })

  it('row 24: create needs CSRF proof and a live session', async () => {
    const body = { name: 'Paths Org', slug: 'paths-org' }
    expect(
      (await rest('POST', '/auth-link/organizations', { cookie: owner, body, csrf: false })).status
    ).toBe(403)
    expect((await rest('POST', '/auth-link/organizations', { body })).status).toBe(401)
    const created = await rest('POST', '/auth-link/organizations', { cookie: owner, body })
    expect(created.status).toBe(201)
    orgId = (created.body as { organization: { id: string } }).organization.id
  })

  it('row 24: invite is manager-only; accept is the invited address only', async () => {
    const added = await rest('POST', '/auth-link/organizations/invite', {
      cookie: owner,
      body: { organizationId: orgId, email: 'org-member@authjs-paths.test', role: 'member' },
    })
    expect(added.status).toBe(201)
    const byMember = await rest('POST', '/auth-link/organizations/invite', {
      cookie: member,
      body: { organizationId: orgId, email: 'org-other@authjs-paths.test', role: 'member' },
    })
    expect(byMember.status).toBe(403)
    const pending = await rest('POST', '/auth-link/organizations/invite', {
      cookie: owner,
      body: { organizationId: orgId, email: 'org-future@authjs-paths.test', role: 'member' },
    })
    expect(pending.status).toBe(201)
    const invitationId = (pending.body as { invitation: { id: string } }).invitation.id
    const stolen = await rest('POST', '/auth-link/organizations/accept', {
      cookie: member,
      body: { invitationId },
    })
    expect(stolen.status).toBe(403)
    const future = await signIn('org-future@authjs-paths.test')
    const accepted = await rest('POST', '/auth-link/organizations/accept', {
      cookie: future,
      body: { invitationId },
    })
    expect(accepted.status).toBe(200)
  })

  it('row 25: a plain member cannot escalate their own membership', async () => {
    const memberId = await hostIdOf(member)
    const rows = await live().find({
      collection: 'memberships',
      where: { and: [{ user: { equals: memberId } }, { organization: { equals: orgId } }] },
      overrideAccess: true,
    })
    const row = rows.docs[0]
    if (row === undefined) {
      throw new Error('membership row missing')
    }
    const attempt = await rest('PATCH', `/memberships/${String(row.id)}`, {
      cookie: member,
      body: { role: 'owner' },
    })
    expect(attempt.status).toBe(403)
    expect(
      (await live().findByID({ collection: 'memberships', id: row.id, overrideAccess: true })).role
    ).toBe('member')
    expect((await rest('GET', '/memberships')).status).toBe(403)
  })
})

describe('row 26: the server-side session verifier over an Auth.js session', () => {
  const verifier = createSessionVerifier({
    baseUrl: ORIGIN,
    fetchImpl: (input, init) => handleEndpoints({ config, request: new Request(input, init) }),
  })

  it('success: the forwarded Auth.js cookie verifies to its user; failure: suspended → null', async () => {
    const { id, cookie } = await linkedUser('verifier@authjs-paths.test')
    const user = await verifier(new Headers({ cookie }))
    expect(user?.id).toBe(id)
    expect(await verifier(new Headers({ cookie: `${sessionCookieName}=forged` }))).toBeNull()
    await suspend(id)
    expect(await verifier(new Headers({ cookie }))).toBeNull()
  })

  it('failure: construction without baseUrl outside development throws', () => {
    expect(() => createSessionVerifier({ environment: { nodeEnv: 'production' } })).toThrow(
      /requires baseUrl/
    )
  })
})

describe('row 27: users writes by other signed-in Auth.js users', () => {
  it("a user may update their own document but not another user's", async () => {
    const alice = await linkedUser('row27-alice@authjs-paths.test')
    const bob = await linkedUser('row27-bob@authjs-paths.test')
    expect(
      (await rest('PATCH', `/users/${alice.id}`, { cookie: alice.cookie, body: {} })).status
    ).toBe(200)
    const other = await rest('PATCH', `/users/${bob.id}`, {
      cookie: alice.cookie,
      body: { email: 'hijacked@authjs-paths.test' },
    })
    // Users update access is a where-constraint (own document); Payload
    // answers a by-id miss under a where policy with 403, not 404.
    expect(other.status).toBe(403)
    expect((await hostDoc(bob.id)).email).toBe('row27-bob@authjs-paths.test')
    const removed = await rest('DELETE', `/users/${bob.id}`, { cookie: alice.cookie })
    expect(removed.status).toBe(403)
    expect((await hostDoc(bob.id)).id).toBeDefined()
  })
})
