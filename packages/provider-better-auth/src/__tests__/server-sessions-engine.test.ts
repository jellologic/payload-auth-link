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
      customRules: { '/sign-up/email': false, '/sign-in/email': false },
    },
  },
})

function authRequest(path: string, init: { method?: string; body?: unknown } = {}): Request {
  const headers: Record<string, string> = {
    origin: ORIGIN,
    ...(init.method !== 'GET' && init.body !== undefined
      ? { 'content-type': 'application/json' }
      : {}),
  }
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: init.method ?? 'GET',
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  })
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
})
