/**
 * Real-engine server session tests: mint, list, and revoke against a
 * real Better Auth 1.7 instance on real Payload storage (SQLite in
 * memory), through `authLinkServer` on a real plugin boot. Every
 * assertion here pins provider-session facts the stub provider cannot
 * produce: the stored expiry, the id a revocation consumes, and the
 * assurance a minted session reports.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink, authLinkServer } from '@payload-auth-link/plugin'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { createHmac } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { twoFactor } from 'better-auth/plugins'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'server-session-engine-secret!!'

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
  // Derive the two-factor plugin's fields and models from Better
  // Auth's own schema — the same declaration route a real app takes.
  autoDeclare: true,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    plugins: [twoFactor()],
    rateLimit: {
      storage: 'database',
      enabled: true,
      window: 60,
      max: 10_000,
      // verify-totp carries BA's own stricter per-endpoint limit; the
      // window-tolerant harness retries would trip it.
      customRules: {
        '/sign-up/email': false,
        '/sign-in/email': false,
        '/two-factor/verify-totp': false,
        // The harness retries enrollment; BA's per-endpoint limit would
        // 429 the second attempt.
        '/two-factor/enable': false,
      },
    },
  },
})

/** Decode an RFC 4648 base32 string (the `secret` of an otpauth:// URI). */
function base32Decode(encoded: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let buffer = 0
  let bits = 0
  const bytes: number[] = []
  for (const char of encoded.replace(/=+$/, '').toUpperCase()) {
    const value = alphabet.indexOf(char)
    if (value === -1) {
      throw new Error(`not a base32 character: ${char}`)
    }
    buffer = ((buffer << 5) | value) & 0xffff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >> bits) & 0xff)
    }
  }
  return Buffer.from(bytes)
}

/**
 * RFC 4226 HOTP (HMAC-SHA1, 6 digits). Dynamic truncation masks ONLY
 * the top bit of the first byte; the other three bytes are taken whole.
 * (The harness this replaced also masked bytes 2 and 3 with 0x7f, so
 * about 3 in 4 counters produced a wrong code: the root cause of the
 * issue #79 test's flakiness.)
 */
function hotp(key: Buffer, counter: number): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', key).update(message).digest()
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f
  const binary = digest.readUInt32BE(offset) & 0x7fffffff
  return String(binary % 1_000_000).padStart(6, '0')
}

/** The current RFC 6238 TOTP code (30s step) for an otpauth:// URI secret. */
function totpNow(uriSecret: string): string {
  return hotp(base32Decode(uriSecret), Math.floor(Date.now() / 30_000))
}

/** The `secret` parameter of the totpURI a /two-factor/enable response carries. */
async function totpSecretOf(enabled: Response): Promise<string> {
  const body = (await enabled.json()) as { totpURI?: unknown }
  if (typeof body.totpURI !== 'string') {
    throw new Error('two-factor enable returned no totpURI')
  }
  const secret = new URL(body.totpURI).searchParams.get('secret')
  if (secret === null) {
    throw new Error('totpURI carries no secret')
  }
  return secret
}

/**
 * Verify the current TOTP code. Deterministic: BA accepts the previous,
 * current, and next 30s step, so a code computed for "now" still
 * verifies when a step boundary falls between generation and check.
 */
function verifyTotp(uriSecret: string, cookie: string): Promise<Response> {
  return engine.auth.handler(
    authRequest('/two-factor/verify-totp', {
      method: 'POST',
      body: { code: totpNow(uriSecret) },
      cookie,
    })
  )
}

/** Enable + enroll 2FA for the user through BA's own endpoints. */
async function enrollUser(email: string): Promise<void> {
  const signIn = await engine.auth.handler(
    authRequest('/sign-in/email', {
      method: 'POST',
      body: { email, password: 'correct-horse-battery' },
    })
  )
  const cookie = cookieOf(signIn)
  const enabled = await engine.auth.handler(
    authRequest('/two-factor/enable', {
      method: 'POST',
      body: { password: 'correct-horse-battery' },
      cookie,
    })
  )
  expect(enabled.status).toBe(200)
  const verified = await verifyTotp(await totpSecretOf(enabled), cookie)
  expect(verified.status, `enroll: ${await verified.text()}`).toBe(200)
}

function authRequest(
  path: string,
  init: { method?: string; body?: unknown; cookie?: string } = {}
): Request {
  const headers: Record<string, string> = {
    origin: ORIGIN,
    ...(init.method !== 'GET' && init.body !== undefined
      ? { 'content-type': 'application/json' }
      : {}),
    ...(init.cookie === undefined ? {} : { cookie: init.cookie }),
  }
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: init.method ?? 'GET',
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  })
}

function cookieOf(response: Response): string {
  const name = engine.sessionCookieNames[0] ?? ''
  const entry = response.headers
    .getSetCookie()
    .find((candidate) => candidate.startsWith(`${name}=`))
  if (entry === undefined) {
    throw new Error('no session cookie on the response')
  }
  return entry.split(';')[0] ?? ''
}

/** Every cookie the response set, exactly as Set-Cookie emitted the pairs. */
function responseCookieHeader(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((entry) => entry.split(';')[0] ?? '')
    .filter((pair) => pair !== '')
    .join('; ')
}
let runCounter = 0

/** Unique per invocation: test retries re-run signUp against the same storage. */
function uniqueEmail(prefix: string): string {
  runCounter += 1
  return `${prefix}-${Date.now()}-${runCounter}@test.dev`
}

let lastEmail = ''

async function signUp(email: string): Promise<void> {
  lastEmail = email
  const response = await engine.auth.handler(
    authRequest('/sign-up/email', {
      method: 'POST',
      body: { name: 'Engine Session', email, password: 'correct-horse-battery' },
    })
  )
  expect(response.status).toBe(200)
}

async function baUserIdOf(email: string): Promise<string> {
  const found = await payload.find({
    collection: 'ba-users',
    where: { email: { equals: email } },
    limit: 1,
    overrideAccess: true,
  })
  const doc = found.docs[0] as { baId?: unknown } | undefined
  const baUserId = typeof doc?.baId === 'string' ? doc.baId : null
  if (baUserId === null) {
    throw new Error(`no ba-users row for ${email}`)
  }
  return baUserId
}

/**
 * Drive the plugin's JIT bridge for real: verify the provider email,
 * present a live BA session at /api/auth-link/session, and get back a
 * linked host document id.
 */
async function bridgeToHostDocument(email: string): Promise<number | string> {
  await payload.update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: true },
    overrideAccess: true,
  })
  const signIn = await engine.auth.handler(
    authRequest('/sign-in/email', {
      method: 'POST',
      body: { email, password: 'correct-horse-battery' },
    })
  )
  const name = engine.sessionCookieNames[0] ?? ''
  const cookie = signIn.headers.getSetCookie().find((entry) => entry.startsWith(`${name}=`))
  if (cookie === undefined) {
    throw new Error('sign-in set no session cookie')
  }
  const bridged = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, {
      headers: { cookie: cookie.split(';')[0] ?? '' },
    }),
  })
  expect(bridged.status).toBe(200)
  const body = (await bridged.json()) as { user?: { id?: unknown } }
  const hostId = body.user?.id
  if (typeof hostId !== 'number' && typeof hostId !== 'string') {
    throw new Error('the bridge resolved no user')
  }
  return hostId
}

async function mint(
  userId: string,
  expiresAt: Date
): Promise<{ sessionId: string; token: string; storedExpiresAt: Date | null }> {
  const create = engine.provider.createProviderSession
  if (create === undefined) {
    throw new Error('the better-auth provider cannot mint sessions')
  }
  const created = await create(userId, { expiresAt })
  if (created.isErr()) {
    throw new Error(created.error.message)
  }
  return created.value
}

async function listSessionsOf(
  userId: string
): Promise<readonly { readonly sessionId: string; readonly expiresAt: Date | null }[]> {
  const list = engine.provider.listProviderSessions
  if (list === undefined) {
    throw new Error('the better-auth provider cannot list sessions')
  }
  const listed = await list(userId)
  if (listed.isErr()) {
    throw new Error(listed.error.message)
  }
  return listed.value
}

beforeAll(async () => {
  config = await buildConfig({
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
        allowServerSessions: true,
        providers: [engine.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
}, 120_000)

describe('real-engine server sessions', () => {
  it('stores the requested TTL, not the default expiry', async () => {
    await signUp('ttl@test.dev')
    const userId = await baUserIdOf('ttl@test.dev')
    const requested = new Date(Date.now() + 300 * 1000)
    const created = await mint(userId, requested)
    // The fact that matters is the STORED row: read it back from the
    // engine itself, identified by its token, not from the mint
    // response.
    const ctx = await engine.auth.$context
    const rows = (await ctx.internalAdapter.listSessions(userId)) as {
      token: string
      expiresAt: Date
    }[]
    const mintedRow = rows.find((row) => row.token === created.token)
    if (mintedRow === undefined) {
      throw new Error('the minted session row is missing')
    }
    const drift = Math.abs(mintedRow.expiresAt.getTime() - requested.getTime())
    expect(drift).toBeLessThan(10_000)
  })

  it('revokeSession deletes the id listSessions hands out, and errors on nothing-deleted', async () => {
    await signUp('revoke@test.dev')
    const userId = await baUserIdOf('revoke@test.dev')
    const created = await mint(userId, new Date(Date.now() + 3_600_000))
    const listedValue = await listSessionsOf(userId)
    if (listedValue.length < 2) {
      throw new Error(`expected the sign-in and minted sessions, got ${String(listedValue.length)}`)
    }
    // Issue #80: the listed handles are NOT credentials — none may
    // equal a live session token (the mint response carries one).
    for (const session of listedValue) {
      expect(session.sessionId).not.toBe(created.token)
    }
    // Any id the LIST hands out must be consumable by the revocation.
    const listedId = listedValue[0]?.sessionId ?? ''
    const revoked = await engine.provider.revokeSession(listedId)
    expect(revoked.isOk()).toBe(true)
    const after = await listSessionsOf(userId)
    expect(after.map((session) => session.sessionId)).not.toContain(listedId)
    // Revoking an id that holds no session must NOT report success.
    const second = await engine.provider.revokeSession(listedId)
    expect(second.isErr()).toBe(true)
    void created
  })

  it('a minted session never reports mfa, even for a 2FA-enrolled user', async () => {
    await signUp('mfa@test.dev')
    const found = await payload.find({
      collection: 'ba-users',
      where: { email: { equals: 'mfa@test.dev' } },
      limit: 1,
      overrideAccess: true,
    })
    const docId = (found.docs[0] as { id?: unknown } | undefined)?.id
    if (docId === undefined) {
      throw new Error('no ba-users row to enroll')
    }
    await payload.update({
      collection: 'ba-users',
      id: docId as number,
      data: { twoFactorEnabled: true },
      overrideAccess: true,
    })
    const userId = await baUserIdOf('mfa@test.dev')
    const created = await mint(userId, new Date(Date.now() + 3_600_000))
    const buildCookie = engine.provider.sessionCookie
    if (buildCookie === undefined) {
      throw new Error('the better-auth provider exposes no sessionCookie')
    }
    const cookie = await buildCookie(created.token)
    const session = await engine.provider.getSession(new Headers({ cookie }))
    if (session.isErr() || session.value === null) {
      throw new Error(session.isErr() ? session.error.message : 'minted cookie resolved nothing')
    }
    // Enrollment is not proof: a minted session carried no 2FA
    // challenge, so it must never claim one.
    expect(session.value.assurance.mfa).toBe(false)
  })

  it('authLinkServer mints, lists, and revokes through one id type on the real plugin', async () => {
    await signUp('server-api@test.dev')
    const hostId = await bridgeToHostDocument('server-api@test.dev')
    const server = authLinkServer(payload)
    const minted = await server.createSessionFor(hostId, {
      reason: 'engine-test',
      ttlSeconds: 300,
    })
    expect(minted.token).toBeTruthy()
    const sessions = await server.listSessions(hostId)
    expect(sessions.length).toBeGreaterThan(0)
    // The id createSessionFor returned must revoke directly.
    await server.revokeSession(minted.sessionId)
    const after = await server.listSessions(hostId)
    expect(after.map((session) => session.sessionId)).not.toContain(minted.sessionId)
    await server.revokeAllForUser(hostId)
    expect(await server.listSessions(hostId)).toEqual([])
  })

  it('the test TOTP generator matches the RFC 4226 / RFC 6238 vectors', () => {
    // RFC 4226 appendix D: key "12345678901234567890", counters 0..9.
    const key = Buffer.from('12345678901234567890')
    const expected = [
      '755224',
      '287082',
      '359152',
      '969429',
      '338314',
      '254676',
      '287922',
      '162583',
      '399871',
      '520489',
    ]
    expect(expected.map((_, counter) => hotp(key, counter))).toEqual(expected)
    // The same key as an otpauth:// base32 secret; RFC 6238 appendix B
    // (T = 59s → step 1, last 6 digits of 94287082).
    expect(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toEqual(key)
    expect(hotp(key, Math.floor(59 / 30))).toBe('287082')
  })

  it("Better Auth's native two-factor sign-in records 'two-factor' (issue #79)", async () => {
    const email = uniqueEmail('native2fa')
    await signUp(email)
    // Enroll through BA's own endpoints, exactly like an app would.
    const firstCookie = cookieOf(
      await engine.auth.handler(
        authRequest('/sign-in/email', {
          method: 'POST',
          body: { email, password: 'correct-horse-battery' },
        })
      )
    )
    expect(firstCookie).toBeTruthy()
    const enabled = await engine.auth.handler(
      authRequest('/two-factor/enable', {
        method: 'POST',
        body: { password: 'correct-horse-battery' },
        cookie: firstCookie,
      })
    )
    expect(enabled.status).toBe(200)
    const secret = await totpSecretOf(enabled)
    const enrolled = await verifyTotp(secret, firstCookie)
    expect(enrolled.status, `enroll: ${await enrolled.text()}`).toBe(200)

    // Fresh password sign-in for the enrolled user: BA responds with
    // twoFactorRedirect — the session exists, created by the PASSWORD
    // step. It must read as password, never prematurely two-factor.
    const pending = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email, password: 'correct-horse-battery' },
      })
    )
    const pendingBody = (await pending.json()) as { twoFactorRedirect?: unknown }
    expect(pendingBody.twoFactorRedirect).toBe(true)
    // BA's 2FA-pending sign-in EXPIRES the session cookie: until the
    // second factor verifies there is NO session at all — a
    // single-factor session is never relabelled, structurally.
    const pendingCookie = responseCookieHeader(pending)
    expect(pendingCookie).toContain('two_factor=')
    // The second factor issues a FRESH session: now — and only now —
    // does a session read as an MFA-proof one.
    const verified = await verifyTotp(secret, pendingCookie)
    expect(verified.status, `verify: ${await verified.text()}`).toBe(200)
    const verifiedCookie = cookieOf(verified)
    const postVerify = await engine.provider.getSession(new Headers({ cookie: verifiedCookie }))
    if (postVerify.isErr() || postVerify.value === null) {
      throw new Error(postVerify.isErr() ? postVerify.error.message : 'no session')
    }
    expect(postVerify.value.assurance.methods).toEqual(['two-factor'])
    expect(postVerify.value.assurance.mfa).toBe(true)
  })

  it('a FAILED verification never relabels the session (advisory: wrong code must not upgrade MFA)', async () => {
    // Enrolled user, live server-minted session (records 'server-mint',
    // mfa false). Sending a WRONG code from that session must leave the
    // session exactly as it was.
    await signUp(uniqueEmail('bypass'))
    const userId = await baUserIdOf(lastEmail)
    await enrollUser(lastEmail)
    const created = await mint(userId, new Date(Date.now() + 3_600_000))
    const buildCookie = engine.provider.sessionCookie
    if (buildCookie === undefined) {
      throw new Error('the better-auth provider exposes no sessionCookie')
    }
    const mintedCookie = await buildCookie(created.token)
    const before = await engine.provider.getSession(new Headers({ cookie: mintedCookie }))
    if (before.isErr() || before.value === null) {
      throw new Error(before.isErr() ? before.error.message : 'no session')
    }
    expect(before.value.assurance.mfa).toBe(false)

    // The attack: a garbage code from the session being used.
    const wrong = await engine.auth.handler(
      authRequest('/two-factor/verify-totp', {
        method: 'POST',
        body: { code: '000000' },
        cookie: mintedCookie,
      })
    )
    expect(wrong.status).toBe(401)

    const after = await engine.provider.getSession(new Headers({ cookie: mintedCookie }))
    if (after.isErr() || after.value === null) {
      throw new Error(after.isErr() ? after.error.message : 'no session')
    }
    expect(after.value.assurance.methods).toEqual(['server-mint'])
    expect(after.value.assurance.mfa).toBe(false)
  })

  it('a wrong code from a NON-enrolled user leaves their session unchanged', async () => {
    await signUp(uniqueEmail('notenrolled'))
    const userId = await baUserIdOf(lastEmail)
    const created = await mint(userId, new Date(Date.now() + 3_600_000))
    const buildCookie = engine.provider.sessionCookie
    if (buildCookie === undefined) {
      throw new Error('the better-auth provider exposes no sessionCookie')
    }
    const mintedCookie = await buildCookie(created.token)
    const wrong = await engine.auth.handler(
      authRequest('/two-factor/verify-totp', {
        method: 'POST',
        body: { code: '123456' },
        cookie: mintedCookie,
      })
    )
    expect(wrong.status).toBe(400)
    const after = await engine.provider.getSession(new Headers({ cookie: mintedCookie }))
    if (after.isErr() || after.value === null) {
      throw new Error(after.isErr() ? after.error.message : 'no session')
    }
    expect(after.value.assurance.mfa).toBe(false)
    expect(after.value.assurance.methods).toEqual(['server-mint'])
  })

  it("a plain password sign-in records 'password' (issue #79)", async () => {
    await signUp('plainpw@test.dev')
    const signedIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'plainpw@test.dev', password: 'correct-horse-battery' },
      })
    )
    expect(signedIn.status).toBe(200)
    const session = await engine.provider.getSession(new Headers({ cookie: cookieOf(signedIn) }))
    if (session.isErr() || session.value === null) {
      throw new Error(session.isErr() ? session.error.message : 'no session')
    }
    expect(session.value.assurance.methods).toEqual(['password'])
    expect(session.value.assurance.mfa).toBe(false)
  })

  describe('step-up: a correct second factor on an EXISTING session (#110)', () => {
    /**
     * An enrolled user holding a live PASSWORD session created AFTER
     * the enrolment (a session that existed while the factor was
     * enrolled can never be stepped up with it, GHSA-xgx5-2cj5-x548):
     * enrol from a first session, complete one TOTP sign-in that
     * trusts the device, then sign in with the password alone — the
     * trusted device skips Better Auth's challenge.
     */
    async function enrolledWithPasswordSession(prefix: string): Promise<{
      secret: string
      passwordCookie: string
      userId: string
    }> {
      const email = uniqueEmail(prefix)
      await signUp(email)
      const userId = await baUserIdOf(email)
      const signInBody = { email, password: 'correct-horse-battery' }
      const enrollCookie = cookieOf(
        await engine.auth.handler(
          authRequest('/sign-in/email', { method: 'POST', body: signInBody })
        )
      )
      const enabled = await engine.auth.handler(
        authRequest('/two-factor/enable', {
          method: 'POST',
          body: { password: 'correct-horse-battery' },
          cookie: enrollCookie,
        })
      )
      expect(enabled.status).toBe(200)
      const secret = await totpSecretOf(enabled)
      const enrolled = await verifyTotp(secret, enrollCookie)
      expect(enrolled.status, `enroll: ${await enrolled.text()}`).toBe(200)
      const challenge = await engine.auth.handler(
        authRequest('/sign-in/email', { method: 'POST', body: signInBody })
      )
      expect(challenge.status).toBe(200)
      const trusted = await engine.auth.handler(
        authRequest('/two-factor/verify-totp', {
          method: 'POST',
          body: { code: totpNow(secret), trustDevice: true },
          cookie: responseCookieHeader(challenge),
        })
      )
      expect(trusted.status).toBe(200)
      const trustCookie = responseCookieHeader(trusted)
        .split('; ')
        .find((pair) => pair.includes('trust_device='))
      if (trustCookie === undefined) {
        throw new Error('no trust-device cookie set')
      }
      const second = await engine.auth.handler(
        authRequest('/sign-in/email', { method: 'POST', body: signInBody, cookie: trustCookie })
      )
      expect(second.status).toBe(200)
      const passwordCookie = cookieOf(second)
      const before = await assuranceOf(passwordCookie)
      expect(before.methods).toEqual(['password'])
      expect(before.mfa).toBe(false)
      return { secret, passwordCookie, userId }
    }

    async function assuranceOf(
      cookie: string
    ): Promise<{ readonly methods: readonly string[] | 'unknown'; readonly mfa: unknown }> {
      const session = await engine.provider.getSession(new Headers({ cookie }))
      if (session.isErr() || session.value === null) {
        throw new Error(session.isErr() ? session.error.message : 'no session')
      }
      return session.value.assurance
    }

    function setsSessionCookie(response: Response): boolean {
      const name = engine.sessionCookieNames[0] ?? ''
      return response.headers.getSetCookie().some((entry) => entry.startsWith(`${name}=`))
    }

    async function mintedCookieFor(userId: string): Promise<string> {
      const created = await mint(userId, new Date(Date.now() + 3_600_000))
      const buildCookie = engine.provider.sessionCookie
      if (buildCookie === undefined) {
        throw new Error('the better-auth provider exposes no sessionCookie')
      }
      return (await buildCookie(created.token)).split(';')[0] ?? ''
    }

    it('relabels a fresh password session two-factor, without any cookie re-set', async () => {
      const { secret, passwordCookie } = await enrolledWithPasswordSession('stepup-fresh')
      // The code is generated inside verifyTotp, right before the call.
      const verified = await verifyTotp(secret, passwordCookie)
      expect(verified.status, `verify: ${await verified.clone().text()}`).toBe(200)
      // The discriminating fact: BA did NOT re-set the session cookie,
      // so only the presented-session path can have relabelled it.
      expect(setsSessionCookie(verified)).toBe(false)
      const after = await assuranceOf(passwordCookie)
      expect(after.methods).toEqual(['two-factor'])
      expect(after.mfa).toBe(true)
    })

    it('relabels an aged session that BA refreshes during the verification', async () => {
      const { secret, passwordCookie } = await enrolledWithPasswordSession('stepup-aged')
      // Age the row past BA's updateAge (default 1 day of a 7-day
      // session): the verification's own session read refreshes it.
      const ctx = await engine.auth.$context
      const token =
        decodeURIComponent(passwordCookie.slice(passwordCookie.indexOf('=') + 1)).split('.')[0] ??
        ''
      await ctx.internalAdapter.updateSession(token, {
        expiresAt: new Date(Date.now() + 2 * 24 * 3600 * 1000),
      })
      const verified = await verifyTotp(secret, passwordCookie)
      expect(verified.status, `verify: ${await verified.clone().text()}`).toBe(200)
      expect(setsSessionCookie(verified)).toBe(true)
      const after = await assuranceOf(passwordCookie)
      expect(after.methods).toEqual(['two-factor'])
      expect(after.mfa).toBe(true)
    })

    it('relabels a server-minted session two-factor', async () => {
      const { secret, userId } = await enrolledWithPasswordSession('stepup-minted')
      const mintedCookie = await mintedCookieFor(userId)
      expect((await assuranceOf(mintedCookie)).methods).toEqual(['server-mint'])
      const verified = await verifyTotp(secret, mintedCookie)
      expect(verified.status, `verify: ${await verified.clone().text()}`).toBe(200)
      const after = await assuranceOf(mintedCookie)
      expect(after.methods).toEqual(['two-factor'])
      expect(after.mfa).toBe(true)
    })

    it('a wrong code leaves the password session unchanged', async () => {
      const { secret, passwordCookie } = await enrolledWithPasswordSession('stepup-wrong')
      // A code wrong for every step BA could accept around now.
      const step = Math.floor(Date.now() / 30_000)
      const key = base32Decode(secret)
      const accepted = new Set(
        [step - 2, step - 1, step, step + 1, step + 2].map((c) => hotp(key, c))
      )
      let wrongCode = '000000'
      while (accepted.has(wrongCode)) {
        wrongCode = String((Number(wrongCode) + 1) % 1_000_000).padStart(6, '0')
      }
      const wrong = await engine.auth.handler(
        authRequest('/two-factor/verify-totp', {
          method: 'POST',
          body: { code: wrongCode },
          cookie: passwordCookie,
        })
      )
      expect(wrong.status).toBe(401)
      const after = await assuranceOf(passwordCookie)
      expect(after.methods).toEqual(['password'])
      expect(after.mfa).toBe(false)
    })

    it('relabels only the session BA authenticated when two session cookies are presented', async () => {
      const { secret, passwordCookie, userId } = await enrolledWithPasswordSession('stepup-two')
      const mintedCookie = await mintedCookieFor(userId)
      // Better Call's parser (BA's own) takes the FIRST session cookie.
      const verified = await verifyTotp(secret, `${passwordCookie}; ${mintedCookie}`)
      expect(verified.status, `verify: ${await verified.clone().text()}`).toBe(200)
      expect((await assuranceOf(passwordCookie)).methods).toEqual(['two-factor'])
      expect((await assuranceOf(mintedCookie)).methods).toEqual(['server-mint'])
    })
  })
})
