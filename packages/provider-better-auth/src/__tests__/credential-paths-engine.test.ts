/**
 * Credential-path matrix rows 8, 12, 13, 14 and the gating half of 19
 * (docs/security-model.md) on a REAL Better Auth engine — real BA 1.7
 * on real Payload storage (SQLite in memory) behind a real authLink
 * boot, driven through `engine.auth.handler` and `handleEndpoints`.
 * Until issue #86 these rows were pinned by the stub provider only.
 *
 * Every row walks its success path AND its failure paths: wrong
 * password / wrong token, expired and revoked sessions, another
 * user's token, a suspended user, and an unproven email.
 *
 * The host users collection uses `auth: { verify: true }` so Payload's
 * own `verify` operation (row 8) exists, and the FIRST operation on
 * the empty database is Payload's `first-register` (row 13) — this
 * file owns one Payload instance, so the order in `beforeAll` matters.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink, authLinkServer, ServerSessionUnsupportedError } from '@payload-auth-link/plugin'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://credential-paths-ba.test'
const SECRET = 'credential-paths-ba-engine-secret!!'
const PASSWORD = 'correct-horse-battery'
const SUSPENDED_UNTIL = '2031-01-01T00:00:00.000Z'
const PAST = '2020-01-01T00:00:00.000Z'
const FOUNDER = 'founder@ba-paths.test'

let config: SanitizedConfig
let payload: Payload | undefined

/** Outbox: the last BA verification / reset URL sent per address. */
const verificationUrls = new Map<string, string>()
const resetTokens = new Map<string, string>()

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!payload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(payload)
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: false,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: ({ user, token }) => {
        resetTokens.set(user.email, token)
        return Promise.resolve()
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      sendVerificationEmail: ({ user, url }) => {
        verificationUrls.set(user.email, url)
        return Promise.resolve()
      },
    },
    user: { changeEmail: { enabled: true, updateEmailWithoutVerification: true } },
  },
})

function live(): Payload {
  if (!payload) {
    throw new Error('Payload not ready')
  }
  return payload
}

function baPost(path: string, body: unknown, cookie?: string): Promise<Response> {
  return engine.auth.handler(
    new Request(`${ORIGIN}/api/auth${path}`, {
      method: 'POST',
      headers: {
        origin: ORIGIN,
        'content-type': 'application/json',
        ...(cookie === undefined ? {} : { cookie }),
      },
      body: JSON.stringify(body),
    })
  )
}

function baGet(url: string, cookie?: string): Promise<Response> {
  return engine.auth.handler(
    new Request(url, {
      headers: { origin: ORIGIN, ...(cookie === undefined ? {} : { cookie }) },
    })
  )
}

/** The BA session cookie pair a response set (throws when absent). */
function sessionCookieOf(response: Response): string {
  const name = engine.sessionCookieNames[0] ?? ''
  const entry = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  if (entry === undefined) {
    throw new Error(`no session cookie set (status ${String(response.status)})`)
  }
  return entry.split(';')[0] ?? ''
}

async function signUp(email: string): Promise<string> {
  const response = await baPost('/sign-up/email', { name: 'Paths', email, password: PASSWORD })
  expect(response.status).toBe(200)
  return sessionCookieOf(response)
}

async function signIn(email: string, password = PASSWORD): Promise<string> {
  const response = await baPost('/sign-in/email', { email, password })
  expect(response.status).toBe(200)
  return sessionCookieOf(response)
}

/** Mark the BA user verified in the provider's own store. */
async function markBaVerified(email: string, verified = true): Promise<void> {
  await live().update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: verified },
    overrideAccess: true,
  })
}

async function baUserId(email: string): Promise<string> {
  const found = await live().find({
    collection: 'ba-users',
    where: { email: { equals: email } },
    limit: 1,
    overrideAccess: true,
  })
  // BA's own user id (`baId`), which its session rows reference.
  const id: unknown = found.docs[0]?.baId
  if (typeof id !== 'string') {
    throw new Error(`no BA user ${email}`)
  }
  return id
}

/** The bearer token inside a signed BA session cookie pair. */
function rawTokenOf(cookie: string): string {
  const value = decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1))
  return value.split('.')[0] ?? ''
}

/** A signed-up, verified, signed-in BA user. */
async function verifiedSession(email: string): Promise<string> {
  await signUp(email)
  await markBaVerified(email)
  return signIn(email)
}

type Reply = { status: number; body: unknown; headers: Headers }

async function rest(
  method: string,
  path: string,
  opts: { cookie?: string; body?: unknown; csrf?: boolean } = {}
): Promise<Reply> {
  const headers: Record<string, string> = { origin: ORIGIN }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.csrf === true) {
    headers['x-auth-link-csrf'] = '1'
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

async function pluginSession(cookie: string): Promise<Reply> {
  return rest('GET', '/auth-link/session', { cookie })
}

/** The host user id the bridge resolved for a cookie (asserts 200). */
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

/** A role manager's proof grant (the runbook's manager action). */
async function grantProof(id: string | number, email: string): Promise<void> {
  await live().update({
    collection: 'users',
    id,
    data: { linkable: true, linkableEmail: email },
    overrideAccess: true,
  })
}

/** The verification token inside a captured BA `/verify-email` URL. */
function tokenOf(url: string | undefined): string {
  const token = url === undefined ? null : new URL(url).searchParams.get('token')
  if (token === null) {
    throw new Error('no verification url captured')
  }
  return token
}

let founderId = ''

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    collections: [{ slug: 'users', auth: { verify: true }, fields: [] }, ...engine.collections],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [engine.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  await engine.auth.$context
  // Row 13: the very first write on the empty database is Payload's
  // own first-register (no manager, no plugin marker).
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

describe('row 13: first-register on an empty DB starts unproven (real BA)', () => {
  it('the first-registered document carries no linkable proof', async () => {
    const doc = await hostDoc(founderId)
    expect(doc.linkable).toBe(false)
    expect(doc.linkableEmail ?? null).toBeNull()
  })

  it('a second first-register is refused once a user exists', async () => {
    const again = await rest('POST', '/users/first-register', {
      body: { email: 'second@ba-paths.test', password: PASSWORD, 'confirm-password': PASSWORD },
    })
    expect(again.status).toBe(403)
    expect(await hostDocByEmail('second@ba-paths.test')).toBeUndefined()
  })

  it('failure: a verified BA identity at the founder address is NOT JIT-linked', async () => {
    const cookie = await verifiedSession(FOUNDER)
    expect((await pluginSession(cookie)).status).toBe(401)
    expect(identitiesOf(await hostDoc(founderId))).toEqual([])
  })

  it('row 19 gate: no linked identity means no session list / revoke-all', async () => {
    await expect(authLinkServer(live()).listSessions(founderId)).rejects.toBeInstanceOf(
      ServerSessionUnsupportedError
    )
    await expect(authLinkServer(live()).revokeAllForUser(founderId)).rejects.toBeInstanceOf(
      ServerSessionUnsupportedError
    )
  })

  it('success: after a manager grants the proof, the same identity links to the founder', async () => {
    await grantProof(founderId, FOUNDER)
    const cookie = await signIn(FOUNDER)
    expect(await hostIdOf(cookie)).toBe(founderId)
    expect(identitiesOf(await hostDoc(founderId))).toHaveLength(1)
  })
})

describe("row 8: Payload's verify token is not linkable proof on its own (real BA)", () => {
  const email = 'verified-only@ba-paths.test'
  let docId = ''

  beforeAll(async () => {
    // Created outside the plugin (no manager, no marker): unproven,
    // unverified, with Payload's own verification token.
    const created = await live().create({
      collection: 'users',
      data: { email, password: PASSWORD, roles: ['user'] },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    docId = String(created.id)
  })

  it('failure: a wrong verification token is refused and verifies nothing', async () => {
    const wrong = await rest('POST', '/users/verify/not-the-token')
    expect(wrong.status).toBeGreaterThanOrEqual(400)
    expect((await hostDoc(docId))._verified).toBe(false)
  })

  it('success: the right token verifies the document and mints no session', async () => {
    const token = (await hostDoc(docId))._verificationToken
    expect(typeof token).toBe('string')
    const verified = await rest('POST', `/users/verify/${String(token)}`)
    expect(verified.status).toBe(200)
    expect(verified.headers.get('set-cookie')).toBeNull()
    expect((await hostDoc(docId))._verified).toBe(true)
  })

  it('failure: `_verified` alone never admits a verified BA identity to the document', async () => {
    const cookie = await verifiedSession(email)
    expect((await pluginSession(cookie)).status).toBe(401)
    expect(identitiesOf(await hostDoc(docId))).toEqual([])
  })

  it('success: `_verified` WITH the manager proof links', async () => {
    await grantProof(docId, email)
    const cookie = await signIn(email)
    expect(await hostIdOf(cookie)).toBe(docId)
  })
})

describe("row 8 / row 1: the provider's own email verification gates the link (real BA)", () => {
  const email = 'unproven-ba@ba-paths.test'
  let docId = ''
  let cookie = ''

  beforeAll(async () => {
    // A proven (manager-vouched) document waiting for its owner.
    const created = await live().create({
      collection: 'users',
      data: { email, password: PASSWORD, roles: ['user'], linkable: true, linkableEmail: email },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    docId = String(created.id)
    cookie = await signUp(email)
  })

  it('failure: an unverified BA email is refused, never linked', async () => {
    expect((await pluginSession(cookie)).status).toBe(401)
    expect(identitiesOf(await hostDoc(docId))).toEqual([])
  })

  it('failure: a wrong BA verification token verifies nothing', async () => {
    const wrong = await baGet(`${ORIGIN}/api/auth/verify-email?token=forged.token.value`)
    expect(wrong.status).toBe(401)
    expect((await pluginSession(cookie)).status).toBe(401)
  })

  it("failure: another user's verification token does not verify this user", async () => {
    const other = 'other-verify@ba-paths.test'
    await signUp(other)
    const verified = await baGet(
      `${ORIGIN}/api/auth/verify-email?token=${tokenOf(verificationUrls.get(other))}`
    )
    expect(verified.status).toBe(200)
    expect((await pluginSession(cookie)).status).toBe(401)
    expect(identitiesOf(await hostDoc(docId))).toEqual([])
  })

  it("success: the owner's own BA verification token unlocks the link", async () => {
    const verified = await baGet(
      `${ORIGIN}/api/auth/verify-email?token=${tokenOf(verificationUrls.get(email))}`
    )
    expect(verified.status).toBe(200)
    expect(await hostIdOf(cookie)).toBe(docId)
  })
})

describe('row 12: Local API with overrideAccess still runs the hooks (real BA)', () => {
  const linked = 'local-api-linked@ba-paths.test'
  const operator = 'local-api-operator@ba-paths.test'
  const suspended = 'local-api-suspended@ba-paths.test'
  let linkedId = ''
  let suspendedId = ''

  beforeAll(async () => {
    const doc = await live().create({
      collection: 'users',
      data: {
        email: linked,
        password: PASSWORD,
        roles: ['user'],
        linkable: true,
        linkableEmail: linked,
        _verified: true,
      },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    linkedId = String(doc.id)
    // Link it through the real engine.
    expect(await hostIdOf(await verifiedSession(linked))).toBe(linkedId)
    await live().create({
      collection: 'users',
      data: { email: operator, password: PASSWORD, roles: ['admin'], _verified: true },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    const suspendedDoc = await live().create({
      collection: 'users',
      data: {
        email: suspended,
        password: PASSWORD,
        roles: ['admin'],
        _verified: true,
        linkable: true,
        linkableEmail: suspended,
      },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    suspendedId = String(suspendedDoc.id)
  })

  it('success: an unlinked operator logs in through the Local API', async () => {
    const result = await live().login({
      collection: 'users',
      data: { email: operator, password: PASSWORD },
    })
    expect(result.token).toEqual(expect.any(String))
  })

  it('failure: Local API login on the BA-linked document is refused (provider-owned)', async () => {
    await expect(
      live().login({ collection: 'users', data: { email: linked, password: PASSWORD } })
    ).rejects.toThrow()
  })

  it('failure: Local API forgot-password on the BA-linked document is refused', async () => {
    await expect(
      live().forgotPassword({ collection: 'users', data: { email: linked } })
    ).rejects.toThrow(/provider-linked/)
  })

  it('failure: a planted reset token on the BA-linked document is refused by the Local API', async () => {
    await live().update({
      collection: 'users',
      id: linkedId,
      data: {
        resetPasswordToken: 'ba-linked-reset-token',
        resetPasswordExpiration: SUSPENDED_UNTIL,
      },
      overrideAccess: true,
    })
    await expect(
      live().resetPassword({
        collection: 'users',
        data: { token: 'ba-linked-reset-token', password: 'RotatedByLocalApi-1' },
        overrideAccess: true,
      })
    ).rejects.toThrow()
    await expect(
      live().login({
        collection: 'users',
        data: { email: linked, password: 'RotatedByLocalApi-1' },
      })
    ).rejects.toThrow()
  })

  it('failure: a suspended operator acting through the Local API is gated; engine writes are not', async () => {
    // The BA engine links and writes its own rows (no req.user) ...
    const cookie = await verifiedSession(suspended)
    expect(await hostIdOf(cookie)).toBe(suspendedId)
    await live().update({
      collection: 'users',
      id: suspendedId,
      data: { suspendedUntil: SUSPENDED_UNTIL, suspendReason: 'row-12' },
      overrideAccess: true,
    })
    const operatorDoc = await hostDoc(suspendedId)
    // ... but a Local API call carrying the suspended operator is refused.
    await expect(
      live().find({
        collection: 'users',
        user: { ...operatorDoc, id: suspendedId, collection: 'users' },
        overrideAccess: false,
      })
    ).rejects.toThrow()
    await expect(
      live().login({ collection: 'users', data: { email: suspended, password: PASSWORD } })
    ).rejects.toThrow()
    // The provider session is refused too (row 1), while the engine
    // itself still signs the user in on its side (its writes run
    // without a req.user, so the row-4 gates skip them).
    expect((await pluginSession(cookie)).status).toBe(401)
    const fresh = await signIn(suspended)
    expect((await pluginSession(fresh)).status).toBe(401)
  })
})

describe('row 14: provider-side change-email resyncs only provider-verified addresses (real BA)', () => {
  const before = 'mover@ba-paths.test'
  const after = 'moved@ba-paths.test'
  let cookie = ''
  let docId = ''

  beforeAll(async () => {
    cookie = await verifiedSession(before)
    docId = await hostIdOf(cookie)
  })

  it('a requested change does nothing until the new address is verified', async () => {
    const requested = await baPost('/change-email', { newEmail: after }, cookie)
    expect(requested.status).toBe(200)
    expect(verificationUrls.get(after)).toBeDefined()
    expect(await hostIdOf(cookie)).toBe(docId)
    expect((await hostDoc(docId)).email).toBe(before)
  })

  it('failure: a forged change-email token changes nothing', async () => {
    const forged = await baGet(`${ORIGIN}/api/auth/verify-email?token=forged.change.token`, cookie)
    expect(forged.status).toBe(401)
    await hostIdOf(cookie)
    expect((await hostDoc(docId)).email).toBe(before)
  })

  it("failure: another user's change-email token is refused for this session", async () => {
    const otherBefore = 'other-mover@ba-paths.test'
    const otherAfter = 'other-moved@ba-paths.test'
    const otherCookie = await verifiedSession(otherBefore)
    await hostIdOf(otherCookie)
    expect((await baPost('/change-email', { newEmail: otherAfter }, otherCookie)).status).toBe(200)
    const stolen = await baGet(
      `${ORIGIN}/api/auth/verify-email?token=${tokenOf(verificationUrls.get(otherAfter))}`,
      cookie
    )
    expect(stolen.status).toBe(401)
    await hostIdOf(cookie)
    expect((await hostDoc(docId)).email).toBe(before)
    expect(await hostDocByEmail(otherAfter)).toBeUndefined()
  })

  it('success: the verified change moves the email AND the linkable proof', async () => {
    const verified = await baGet(
      `${ORIGIN}/api/auth/verify-email?token=${tokenOf(verificationUrls.get(after))}`,
      cookie
    )
    expect(verified.status).toBe(200)
    expect(await hostIdOf(cookie)).toBe(docId)
    const doc = await hostDoc(docId)
    expect(doc.email).toBe(after)
    expect(doc.linkable).toBe(true)
    expect(doc.linkableEmail).toBe(after)
  })

  it('failure: the OLD address no longer reaches the moved document', async () => {
    const squatter = await verifiedSession(before)
    const reply = await pluginSession(squatter)
    if (reply.status === 200) {
      const id = (reply.body as { user?: { id?: unknown } }).user?.id
      expect(String(id)).not.toBe(docId)
    }
    expect(identitiesOf(await hostDoc(docId))).toHaveLength(1)
  })

  it('failure: an UNVERIFIED provider-side change never resyncs the Payload email', async () => {
    const unverifiedBefore = 'unverified-mover@ba-paths.test'
    const unverifiedAfter = 'unverified-moved@ba-paths.test'
    const moverCookie = await verifiedSession(unverifiedBefore)
    const moverId = await hostIdOf(moverCookie)
    // BA lets an unverified account change its address immediately
    // (`updateEmailWithoutVerification`): the new address is unproven.
    await markBaVerified(unverifiedBefore, false)
    const changed = await baPost('/change-email', { newEmail: unverifiedAfter }, moverCookie)
    expect(changed.status).toBe(200)
    const reply = await pluginSession(moverCookie)
    // The linked session keeps working on the Payload side, but under
    // the last provider-VERIFIED address.
    expect(reply.status).toBe(200)
    expect((reply.body as { user?: { email?: unknown } }).user?.email).toBe(unverifiedBefore)
    const doc = await hostDoc(moverId)
    expect(doc.email).toBe(unverifiedBefore)
    expect(doc.linkableEmail).toBe(unverifiedBefore)
    expect(await hostDocByEmail(unverifiedAfter)).toBeUndefined()
  })

  it('failure: suspension still refuses the session after a provider-side change', async () => {
    await live().update({
      collection: 'users',
      id: docId,
      data: { suspendedUntil: SUSPENDED_UNTIL },
      overrideAccess: true,
    })
    expect((await pluginSession(cookie)).status).toBe(401)
    // Suspending also revoked the provider sessions: a fresh sign-in
    // at the NEW address is refused while suspended ...
    expect((await pluginSession(await signIn(after))).status).toBe(401)
    await live().update({
      collection: 'users',
      id: docId,
      data: { suspendedUntil: null },
      overrideAccess: true,
    })
    // ... the revoked cookie stays dead after the lift, and a fresh
    // sign-in reaches the same (moved) document.
    expect((await pluginSession(cookie)).status).toBe(401)
    expect(await hostIdOf(await signIn(after))).toBe(docId)
  })
})

describe('row 14: provider-side change-password (real BA)', () => {
  const email = 'rotator@ba-paths.test'
  const rotated = 'rotated-horse-battery'
  let current = ''
  let otherDevice = ''
  let docId = ''

  beforeAll(async () => {
    current = await verifiedSession(email)
    otherDevice = await signIn(email)
    docId = await hostIdOf(current)
    expect(await hostIdOf(otherDevice)).toBe(docId)
  })

  it('failure: a wrong current password changes nothing', async () => {
    const wrong = await baPost(
      '/change-password',
      { currentPassword: 'not-the-password', newPassword: rotated, revokeOtherSessions: true },
      current
    )
    expect(wrong.status).toBe(400)
    expect(await hostIdOf(otherDevice)).toBe(docId)
    expect((await baPost('/sign-in/email', { email, password: rotated })).status).toBe(401)
  })

  it('success: the change revokes other sessions; the provider owns the credential', async () => {
    const changed = await baPost(
      '/change-password',
      { currentPassword: PASSWORD, newPassword: rotated, revokeOtherSessions: true },
      current
    )
    expect(changed.status).toBe(200)
    expect((await pluginSession(otherDevice)).status).toBe(401)
    const fresh = sessionCookieOf(changed)
    expect(await hostIdOf(fresh)).toBe(docId)
    // The Payload document keeps no usable local credential.
    await expect(
      live().login({ collection: 'users', data: { email, password: rotated } })
    ).rejects.toThrow()
    expect(
      (await rest('POST', '/users/login', { body: { email, password: rotated } })).status
    ).not.toBe(200)
  })
})

describe('row 14: provider-side reset-password (real BA)', () => {
  const email = 'resetter@ba-paths.test'
  const rotated = 'reset-horse-battery'
  let cookie = ''
  let docId = ''

  beforeAll(async () => {
    cookie = await verifiedSession(email)
    docId = await hostIdOf(cookie)
  })

  async function requestReset(): Promise<string> {
    resetTokens.delete(email)
    const requested = await baPost('/request-password-reset', {
      email,
      redirectTo: `${ORIGIN}/reset`,
    })
    expect(requested.status).toBe(200)
    const token = resetTokens.get(email)
    if (token === undefined) {
      throw new Error('no reset token captured')
    }
    return token
  }

  it('failure: a wrong reset token is refused', async () => {
    await requestReset()
    const wrong = await baPost('/reset-password', { token: 'not-a-token', newPassword: rotated })
    expect(wrong.status).toBe(400)
    expect(await hostIdOf(cookie)).toBe(docId)
  })

  it('failure: an expired reset token is refused', async () => {
    const token = await requestReset()
    await live().update({
      collection: 'ba-verifications',
      where: { identifier: { equals: `reset-password:${token}` } },
      data: { expiresAt: PAST },
      overrideAccess: true,
    })
    const expired = await baPost('/reset-password', { token, newPassword: rotated })
    expect(expired.status).toBe(400)
    expect(await hostIdOf(cookie)).toBe(docId)
  })

  it('success: the reset revokes live sessions; the new password signs in', async () => {
    const token = await requestReset()
    const reset = await baPost('/reset-password', { token, newPassword: rotated })
    expect(reset.status).toBe(200)
    expect((await pluginSession(cookie)).status).toBe(401)
    const fresh = await signIn(email, rotated)
    expect(await hostIdOf(fresh)).toBe(docId)
    // A used token is single-use.
    const replay = await baPost('/reset-password', { token, newPassword: 'third-horse-battery' })
    expect(replay.status).toBe(400)
  })

  it('failure: suspension refuses the session the reset produced', async () => {
    await live().update({
      collection: 'users',
      id: docId,
      data: { suspendedUntil: SUSPENDED_UNTIL },
      overrideAccess: true,
    })
    const fresh = await signIn(email, rotated)
    expect((await pluginSession(fresh)).status).toBe(401)
  })
})

describe('session lifecycle negatives and the row 19 gates (real BA)', () => {
  it('failure: an expired BA session is refused', async () => {
    const email = 'expired@ba-paths.test'
    const cookie = await verifiedSession(email)
    await hostIdOf(cookie)
    await live().update({
      collection: 'ba-sessions',
      where: { userId: { equals: await baUserId(email) } },
      data: { expiresAt: PAST },
      overrideAccess: true,
    })
    expect((await pluginSession(cookie)).status).toBe(401)
  })

  it('failure: a revoked BA session is refused; the sibling session survives', async () => {
    const email = 'revoked@ba-paths.test'
    const first = await verifiedSession(email)
    const second = await signIn(email)
    const userId = await hostIdOf(first)
    expect(await hostIdOf(second)).toBe(userId)
    // Resolve the FIRST cookie's opaque handle from the provider's own
    // session row (handles are row ids, never the bearer token).
    const rows = await live().find({
      collection: 'ba-sessions',
      where: { token: { equals: rawTokenOf(first) } },
      limit: 1,
      overrideAccess: true,
    })
    const row = rows.docs[0]
    const listed = (await authLinkServer(live()).listSessions(userId)).map((s) => s.sessionId)
    const handle = listed.find((id) => id === row?.baId || id === String(row?.id))
    if (handle === undefined) {
      throw new Error('the listed handles do not include the first session')
    }
    await authLinkServer(live()).revokeSession(handle)
    expect((await pluginSession(first)).status).toBe(401)
    expect(await hostIdOf(second)).toBe(userId)
    // Revoking the same handle twice fails loudly (it is gone).
    await expect(authLinkServer(live()).revokeSession(handle)).rejects.toThrow(/^revokeSession: /)
  })

  it("row 19: a list returns only the user's own handles, never a bearer token", async () => {
    const mine = await verifiedSession('list-mine@ba-paths.test')
    const theirs = await verifiedSession('list-theirs@ba-paths.test')
    const myId = await hostIdOf(mine)
    const theirId = await hostIdOf(theirs)
    const myHandles = (await authLinkServer(live()).listSessions(myId)).map((s) => s.sessionId)
    const theirHandles = (await authLinkServer(live()).listSessions(theirId)).map(
      (s) => s.sessionId
    )
    expect(myHandles.some((handle) => theirHandles.includes(handle))).toBe(false)
    expect(myHandles).not.toContain(rawTokenOf(mine))
  })

  it("row 19: another user's cookie token is not a revocation handle", async () => {
    const victim = await verifiedSession('token-victim@ba-paths.test')
    await hostIdOf(victim)
    await expect(authLinkServer(live()).revokeSession(rawTokenOf(victim))).rejects.toThrow(
      /^revokeSession: /
    )
    expect((await pluginSession(victim)).status).toBe(200)
  })
})
