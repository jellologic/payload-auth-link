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
      },
    },
  },
})

/**
 * Verify a TOTP code, tolerating the 30s window boundary: BA's OTP
 * verifies the current, previous, and next steps, and this harness's
 * code generation can land a step off the endpoint's clock — try each
 * window until one accepts. (Empirically the previous step is the one
 * that lands; see the derivation sweep this helper replaced.)
 */
async function verifyTotpResilient(uriSecret: string, cookie: string): Promise<Response> {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let buffer = 0
  let bits = 0
  const key: number[] = []
  for (const char of uriSecret) {
    if (char === '=') break
    const value = alphabet.indexOf(char)
    if (value === -1) continue
    buffer = (buffer << 5) | value
    bits += 5
    while (bits >= 8) {
      bits -= 8
      key.push((buffer >> bits) & 255)
    }
  }
  const keyBuffer = Buffer.from(key)
  const now = Date.now()
  // BA's verify window is ±1 step around ITS clock; the harness clock
  // can sit one step off. BA allows 5 attempts per pending 2FA cookie.
  for (const offsetSeconds of [0, -30, 30, -60, 60]) {
    const counter = Buffer.alloc(8)
    counter.writeBigUInt64BE(BigInt(Math.floor((now + offsetSeconds * 1000) / 30_000)))
    const digest = createHmac('sha1', keyBuffer).update(counter).digest()
    const offset = (digest[digest.length - 1] ?? 0) & 0x0f
    const binary =
      ((digest[offset] ?? 0) & 0x7f) * 2 ** 24 +
      ((digest[offset + 1] ?? 0) & 0x7f) * 2 ** 16 +
      ((digest[offset + 2] ?? 0) & 0x7f) * 2 ** 8 +
      (digest[offset + 3] ?? 0)
    const code = String(binary % 1_000_000).padStart(6, '0')
    const response = await engine.auth.handler(
      authRequest('/two-factor/verify-totp', {
        method: 'POST',
        body: { code },
        cookie,
      })
    )
    if (response.status === 200) {
      return response
    }
  }
  throw new Error('TOTP verification failed across all time windows')
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
async function signUp(email: string): Promise<void> {
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

  // retry: the pending verification races the 30s TOTP step boundary —
  // a code computed for step N can be validated at N+1, and BA's
  // per-endpoint window sweep in the helper covers ±2 steps; vitest
  // retries absorb the remaining boundary cases.
  it(
    "Better Auth's native two-factor sign-in records 'two-factor' (issue #79)",
    { retry: 2 },
    async () => {
      // Unique email per attempt: a retry re-runs signUp against the
      // same storage, and BA 422s duplicate emails.
      const email = `native2fa-${Date.now()}-${Math.floor(Math.random() * 1e6)}@test.dev`
      await signUp(email)
      const userId = await baUserIdOf(email)
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
      // Re-enable on a window-race failure: a fresh secret sidesteps a
      // boundary crossed mid-verification.
      let secret: string | null = null
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const enabled = await engine.auth.handler(
          authRequest('/two-factor/enable', {
            method: 'POST',
            body: { password: 'correct-horse-battery' },
            cookie: firstCookie,
          })
        )
        expect(enabled.status).toBe(200)
        const enabledBody = (await enabled.json()) as { totpURI?: unknown }
        if (typeof enabledBody.totpURI !== 'string') {
          throw new Error('two-factor enable returned no totpURI')
        }
        const candidate = new URL(enabledBody.totpURI).searchParams.get('secret')
        if (candidate === null) {
          throw new Error('totpURI carries no secret')
        }
        const enrolled = await verifyTotpResilient(candidate, firstCookie)
        if (enrolled.status === 200) {
          secret = candidate
          break
        }
        if (attempt === 1) {
          expect(enrolled.status, `enroll: ${await enrolled.text()}`).toBe(200)
        }
      }
      if (secret === null) {
        throw new Error('unreachable: enrollment retry loop exhausted without failing')
      }

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
      const verified = await verifyTotpResilient(secret, pendingCookie)
      expect(verified.status, `verify: ${await verified.text()}`).toBe(200)
      const verifiedCookie = cookieOf(verified)
      const postVerify = await engine.provider.getSession(new Headers({ cookie: verifiedCookie }))
      if (postVerify.isErr() || postVerify.value === null) {
        throw new Error(postVerify.isErr() ? postVerify.error.message : 'no session')
      }
      expect(postVerify.value.assurance.methods).toEqual(['two-factor'])
      expect(postVerify.value.assurance.mfa).toBe(true)
      void userId
    }
  )

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
})
