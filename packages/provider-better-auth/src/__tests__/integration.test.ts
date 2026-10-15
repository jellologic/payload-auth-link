/**
 * Integration tests: a real Better Auth engine on real Payload storage
 * (SQLite in memory), driven through `auth.handler` and Payload's
 * `handleEndpoints`. Covers signup, sessions, the plugin JIT bridge,
 * updates, revocation, deletion, direct adapter operations on every model,
 * joins, and session cookie-name parity with Better Auth's own getter.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'better-auth-integration-secret!!'

let config: SanitizedConfig
let payload: Payload
let latePayload: Payload | undefined
// Engine construction is synchronous (Payload resolves through the thunk),
// so it lives at module scope with its full inferred type: `Auth` is
// invariant in its options and cannot be re-declared.
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: {
      storage: 'database',
      enabled: true,
      window: 60,
      max: 10_000,
      // Special per-path rules would throttle the suite; the global rule
      // still exercises database-backed persistence.
      customRules: { '/sign-up/email': false, '/sign-in/email': false, '/delete-user': false },
    },
    user: { deleteUser: { enabled: true } },
  },
})

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function sessionCookieFrom(response: Response, name: string): string {
  const setCookies = response.headers.getSetCookie()
  const match = setCookies.find((entry) => entry.startsWith(`${name}=`))
  if (!match) {
    throw new Error(`response sets no ${name} cookie: ${setCookies.join('; ')}`)
  }
  const pair = match.split(';', 1)[0]
  if (!pair) {
    throw new Error(`malformed set-cookie entry: ${match}`)
  }
  return pair
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

function pluginRequest(path: string, cookie?: string): Request {
  return new Request(`${ORIGIN}/api${path}`, {
    headers: cookie === undefined ? {} : { cookie },
  })
}

async function countDocs(collection: string): Promise<number> {
  const found = await payload.count({ collection, overrideAccess: true })
  return found.totalDocs
}

async function signUpUser(email: string, name: string): Promise<void> {
  const response = await engine.auth.handler(
    authRequest('/sign-up/email', {
      method: 'POST',
      body: { name, email, password: 'correct-horse-battery' },
    })
  )
  expect(response.status).toBe(200)
}

async function baUserRow(email: string): Promise<Record<string, unknown> | null> {
  const found = await payload.find({
    collection: 'ba-users',
    where: { email: { equals: email } },
    limit: 1,
    overrideAccess: true,
  })
  const [doc] = found.docs as unknown[]
  return isRecord(doc) ? doc : null
}

/**
 * Stamp a provider user's email verified, mirroring the examples'
 * dev-only auto-verify route. The plugin gates JIT provisioning on a
 * verified provider email, so bridge tests verify first; the refusal
 * path itself is pinned below.
 */
async function verifyEmail(email: string): Promise<void> {
  const updated = await payload.update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: true },
    overrideAccess: true,
  })
  if (updated.docs.length !== 1) {
    throw new Error(`expected one ba-users row for ${email}`)
  }
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
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
  latePayload = payload
  // Surface adapter/schema init failures here, not on first request.
  await engine.auth.$context
}, 120_000)

describe('credentials flow', () => {
  it('signs up a user into Payload collections', async () => {
    const response = await engine.auth.handler(
      authRequest('/sign-up/email', {
        method: 'POST',
        body: {
          name: 'Ada Lovelace',
          email: 'ada@test.dev',
          password: 'correct-horse-battery',
        },
      })
    )
    expect(response.status).toBe(200)
    const cookie = sessionCookieFrom(response, engine.sessionCookieNames[0] ?? '')
    expect(await countDocs('ba-users')).toBe(1)
    expect(await countDocs('ba-accounts')).toBe(1)
    expect(await countDocs('ba-sessions')).toBe(1)

    const session = await engine.auth.handler(authRequest('/get-session', { cookie }))
    expect(session.status).toBe(200)
    const body: unknown = await session.json()
    if (!isRecord(body) || !isRecord(body.user)) {
      throw new Error('get-session returned no user')
    }
    expect(body.user['email']).toBe('ada@test.dev')
  })

  it('rejects a duplicate signup', async () => {
    const response = await engine.auth.handler(
      authRequest('/sign-up/email', {
        method: 'POST',
        body: { name: 'Ada Again', email: 'ada@test.dev', password: 'correct-horse-battery' },
      })
    )
    expect(response.status).toBeGreaterThanOrEqual(400)
  })
})

describe('plugin bridge', () => {
  it('provisions the Payload user just-in-time at session verification', async () => {
    const signedIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'ada@test.dev', password: 'correct-horse-battery' },
      })
    )
    expect(signedIn.status).toBe(200)
    const cookie = sessionCookieFrom(signedIn, engine.sessionCookieNames[0] ?? '')
    await verifyEmail('ada@test.dev')

    const response = await handleEndpoints({
      config,
      request: pluginRequest('/auth-link/session', cookie),
    })
    expect(response.status).toBe(200)
    const body: unknown = await response.json()
    if (!isRecord(body) || !isRecord(body.user)) {
      throw new Error('plugin session returned no user')
    }
    expect(body.user['email']).toBe('ada@test.dev')
    expect(body.user['roles']).toEqual(['user'])
  })

  it('refuses to provision a Payload user for an unverified email', async () => {
    const signedUp = await engine.auth.handler(
      authRequest('/sign-up/email', {
        method: 'POST',
        body: {
          name: 'Unverified User',
          email: 'unverified@test.dev',
          password: 'correct-horse-battery',
        },
      })
    )
    expect(signedUp.status).toBe(200)
    const cookie = sessionCookieFrom(signedUp, engine.sessionCookieNames[0] ?? '')

    const response = await handleEndpoints({
      config,
      request: pluginRequest('/auth-link/session', cookie),
    })
    expect(response.status).toBe(401)
    const kept = await payload.find({
      collection: 'users',
      where: { email: { equals: 'unverified@test.dev' } },
      limit: 1,
      overrideAccess: true,
    })
    expect(kept.totalDocs).toBe(0)
  })

  it('updates the provider profile through the adapter', async () => {
    const signedIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'ada@test.dev', password: 'correct-horse-battery' },
      })
    )
    const cookie = sessionCookieFrom(signedIn, engine.sessionCookieNames[0] ?? '')
    const updated = await engine.auth.handler(
      authRequest('/update-user', { method: 'POST', body: { name: 'Ada King' }, cookie })
    )
    expect(updated.status).toBe(200)
    const stored = await payload.find({
      collection: 'ba-users',
      where: { email: { equals: 'ada@test.dev' } },
      limit: 1,
      overrideAccess: true,
    })
    expect((stored.docs[0] as { name?: unknown } | undefined)?.name).toBe('Ada King')
  })
})

describe('port revocation', () => {
  it('revokes the session and invalidates the plugin session', async () => {
    const signedIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'ada@test.dev', password: 'correct-horse-battery' },
      })
    )
    const cookie = sessionCookieFrom(signedIn, engine.sessionCookieNames[0] ?? '')
    const headers = new Headers({ cookie })
    const live = await engine.provider.getSession(headers)
    expect(live.isOk() && live.value?.email).toBe('ada@test.dev')
    if (live.isErr() || !live.value) {
      throw new Error('expected a live provider session')
    }
    const revoked = await engine.provider.revokeSession(live.value.sessionId)
    expect(revoked.isOk()).toBe(true)
    const gone = await engine.provider.getSession(headers)
    expect(gone.isOk() && gone.value).toBeNull()
    const response = await handleEndpoints({
      config,
      request: pluginRequest('/auth-link/session', cookie),
    })
    expect(response.status).toBe(401)
  })
})

describe('adapter operations', () => {
  it('round-trips verifications with select, sort, offset, and count', async () => {
    const ctx = await engine.auth.$context
    await ctx.adapter.create({
      model: 'verification',
      data: { identifier: 'test', value: 'v-1', expiresAt: new Date('2026-01-01T00:00:00.000Z') },
    })
    await ctx.adapter.create({
      model: 'verification',
      data: { identifier: 'test', value: 'v-2', expiresAt: new Date('2026-06-01T00:00:00.000Z') },
    })
    expect(
      await ctx.adapter.count({
        model: 'verification',
        where: [{ field: 'identifier', value: 'test' }],
      })
    ).toBe(2)
    const second = await ctx.adapter.findMany<{ value: string; identifier?: string }>({
      model: 'verification',
      where: [{ field: 'identifier', value: 'test' }],
      sortBy: { field: 'expiresAt', direction: 'asc' },
      limit: 1,
      offset: 1,
      select: ['value'],
    })
    expect(second).toHaveLength(1)
    expect(second[0]?.value).toBe('v-2')
    // The factory normalizes output shape: unselected fields come back
    // undefined (same as the memory adapter), so `select` is honored as a
    // fetch hint rather than a strict projection.
    expect(second[0]?.identifier).toBeUndefined()
    const removed = await ctx.adapter.deleteMany({
      model: 'verification',
      where: [{ field: 'identifier', value: 'test' }],
    })
    expect(removed).toBe(2)
    expect(await ctx.adapter.count({ model: 'verification' })).toBe(0)
  })

  it('throws AdapterOperationError on storage drift instead of returning a malformed row (TYP-9)', async () => {
    const ctx = await engine.auth.$context
    await ctx.adapter.create({
      model: 'verification',
      data: { identifier: 'drift', value: 'v', expiresAt: new Date('2026-01-01T00:00:00.000Z') },
    })
    const lookup = () =>
      ctx.adapter.findOne({
        model: 'verification',
        where: [{ field: 'identifier', value: 'drift' }],
      })
    // Raw database write (bypasses field validation, like real drift):
    // the row loses its Better Auth id.
    await payload.db.updateOne({
      collection: 'ba-verifications',
      where: { identifier: { equals: 'drift' } },
      data: { baId: '' },
    })
    await expect(lookup()).rejects.toThrow(/missing baId/)
    // SQL adapters cannot even hold an unparseable date (Drizzle formats
    // on read), but document stores can: serve one such row, once.
    const find = vi.spyOn(payload, 'find').mockResolvedValueOnce({
      docs: [{ id: 1, baId: 'v-drift', identifier: 'drift', value: 'v', expiresAt: 'not-a-date' }],
    } as unknown as Awaited<ReturnType<Payload['find']>>)
    await expect(lookup()).rejects.toThrow(/expiresAt is not a valid date/)
    find.mockRestore()
    await payload.db.deleteMany({
      collection: 'ba-verifications',
      where: { identifier: { equals: 'drift' } },
    })
  })

  it('round-trips rate limits with update and updateMany', async () => {
    const ctx = await engine.auth.$context
    await ctx.adapter.create({
      model: 'rateLimit',
      data: { key: 'rl-1', count: 1, lastRequest: Date.now() },
    })
    const found = await ctx.adapter.findOne<{ count: number }>({
      model: 'rateLimit',
      where: [{ field: 'key', value: 'rl-1' }],
    })
    expect(found?.count).toBe(1)
    const updated = await ctx.adapter.update<{ count: number }>({
      model: 'rateLimit',
      where: [{ field: 'key', value: 'rl-1' }],
      update: { count: 2 },
    })
    expect(updated?.count).toBe(2)
    const touched = await ctx.adapter.updateMany({
      model: 'rateLimit',
      where: [{ field: 'count', operator: 'gte', value: 1 }],
      update: { count: 3 },
    })
    expect(touched).toBeGreaterThanOrEqual(1)
    const removed = await ctx.adapter.deleteMany({
      model: 'rateLimit',
      where: [{ field: 'key', value: 'rl-1' }],
    })
    expect(removed).toBe(1)
  })

  it('joins sessions to users', async () => {
    const ctx = await engine.auth.$context
    const rows = await ctx.adapter.findMany({
      model: 'session',
      where: [],
      limit: 10,
      join: { user: true },
    })
    expect(rows.length).toBeGreaterThan(0)
    const emails: unknown[] = []
    for (const row of rows) {
      if (!isRecord(row) || !isRecord(row['user'])) {
        throw new Error('joined session misses its user')
      }
      emails.push(row['user']['email'])
    }
    // Earlier tests create several sessions (ada signs in repeatedly,
    // the refusal test adds its own); every row must join its user and
    // ada's sessions must be among them.
    expect(emails).toContain('ada@test.dev')
  })

  it('update exact-matches insensitive clauses instead of like over-matching', async () => {
    // The decoy contains the target address, so the translated `like`
    // matches both rows and only the post-filter exacts. Decoy second:
    // Payload returns newest first, so unfixed code hits the decoy.
    await signUpUser('ci-update@test.dev', 'Exact')
    await signUpUser('ci-update@test.dev.evil.com', 'Decoy')
    const ctx = await engine.auth.$context
    const updated = await ctx.adapter.update<{ email: string; name: string }>({
      model: 'user',
      where: [{ field: 'email', value: 'CI-UPDATE@TEST.DEV', mode: 'insensitive' }],
      update: { name: 'Exacted' },
    })
    expect(updated?.email).toBe('ci-update@test.dev')
    expect(updated?.name).toBe('Exacted')
    expect((await baUserRow('ci-update@test.dev.evil.com'))?.['name']).toBe('Decoy')
  })

  it('updateMany rewrites only exact insensitive matches', async () => {
    await signUpUser('ci-bulk@test.dev.evil.com', 'Decoy')
    await signUpUser('ci-bulk@test.dev', 'Exact')
    const ctx = await engine.auth.$context
    const touched = await ctx.adapter.updateMany({
      model: 'user',
      where: [{ field: 'email', value: 'CI-BULK@TEST.DEV', mode: 'insensitive' }],
      update: { name: 'Bulk' },
    })
    expect(touched).toBe(1)
    expect((await baUserRow('ci-bulk@test.dev'))?.['name']).toBe('Bulk')
    expect((await baUserRow('ci-bulk@test.dev.evil.com'))?.['name']).toBe('Decoy')
  })

  it('delete removes only the exact insensitive match', async () => {
    // Decoy second (newest-first order): unfixed code deletes the decoy.
    await signUpUser('ci-delete@test.dev', 'Exact')
    await signUpUser('ci-delete@test.dev.evil.com', 'Decoy')
    const ctx = await engine.auth.$context
    await ctx.adapter.delete({
      model: 'user',
      where: [{ field: 'email', value: 'CI-DELETE@TEST.DEV', mode: 'insensitive' }],
    })
    expect(await baUserRow('ci-delete@test.dev')).toBeNull()
    expect((await baUserRow('ci-delete@test.dev.evil.com'))?.['name']).toBe('Decoy')
  })

  it('deleteMany removes only exact insensitive matches', async () => {
    await signUpUser('ci-del-many@test.dev.evil.com', 'Decoy')
    await signUpUser('ci-del-many@test.dev', 'Exact')
    const ctx = await engine.auth.$context
    const removed = await ctx.adapter.deleteMany({
      model: 'user',
      where: [{ field: 'email', value: 'CI-DEL-MANY@TEST.DEV', mode: 'insensitive' }],
    })
    expect(removed).toBe(1)
    expect(await baUserRow('ci-del-many@test.dev')).toBeNull()
    expect((await baUserRow('ci-del-many@test.dev.evil.com'))?.['name']).toBe('Decoy')
  })

  it('update with an insensitive clause and no exact match touches nothing', async () => {
    // Order-independent guard: only the decoy `like`-matches, so
    // unfixed code rewrites it while fixed code finds no exact row.
    await signUpUser('ci-noexact@test.dev.evil.com', 'Decoy')
    const ctx = await engine.auth.$context
    const updated = await ctx.adapter.update<{ email: string; name: string }>({
      model: 'user',
      where: [{ field: 'email', value: 'CI-NOEXACT@TEST.DEV', mode: 'insensitive' }],
      update: { name: 'Wrong' },
    })
    expect(updated).toBeNull()
    expect((await baUserRow('ci-noexact@test.dev.evil.com'))?.['name']).toBe('Decoy')
  })

  it('delete with an insensitive clause and no exact match removes nothing', async () => {
    await signUpUser('ci-noexact-del@test.dev.evil.com', 'Decoy')
    const ctx = await engine.auth.$context
    await ctx.adapter.delete({
      model: 'user',
      where: [{ field: 'email', value: 'CI-NOEXACT-DEL@TEST.DEV', mode: 'insensitive' }],
    })
    expect((await baUserRow('ci-noexact-del@test.dev.evil.com'))?.['name']).toBe('Decoy')
  })

  it('updateMany with empty where writes nothing', async () => {
    const before = await baUserRow('ada@test.dev')
    const users = await countDocs('ba-users')
    const ctx = await engine.auth.$context
    const touched = await ctx.adapter.updateMany({
      model: 'user',
      where: [],
      update: { name: 'Nobody' },
    })
    expect(touched).toBe(0)
    expect(await countDocs('ba-users')).toBe(users)
    // Any Payload update rewrites updatedAt: an untouched stamp plus an
    // untouched name proves no row was written.
    const after = await baUserRow('ada@test.dev')
    expect(after?.['name']).toBe(before?.['name'])
    expect(after?.['updatedAt']).toBe(before?.['updatedAt'])
  })

  it('deleteMany with empty where throws and deletes nothing', async () => {
    const users = await countDocs('ba-users')
    const ctx = await engine.auth.$context
    await expect(ctx.adapter.deleteMany({ model: 'user', where: [] })).rejects.toThrow(
      'refusing empty where clause'
    )
    expect(await countDocs('ba-users')).toBe(users)
  })

  it('persists rate-limit state to Payload', async () => {
    expect(await countDocs('ba-rate-limits')).toBeGreaterThan(0)
  })
})

describe('session cookie names', () => {
  it('matches Better Auth’s own cookie getter', async () => {
    const ctx = await engine.auth.$context
    expect(ctx.createAuthCookie('session_token').name).toBe(engine.sessionCookieNames[0])
  })

  it('matches with the cookie cache enabled', () => {
    const cached = createBetterAuthEngine({
      getPayload: () => Promise.resolve(payload),
      options: {
        baseURL: ORIGIN,
        secret: SECRET,
        session: { cookieCache: { enabled: true } },
      },
    })
    expect(cached.sessionCookieNames).toEqual([
      'better-auth.session_token',
      'better-auth.session_data',
    ])
    return cached.auth.$context.then((ctx) => {
      expect(ctx.createAuthCookie('session_data').name).toBe(cached.sessionCookieNames[1])
    })
  })
})

describe('server-session cookie (#54, #72)', () => {
  it('mints a signed cookie Better Auth itself accepts', async () => {
    await signUpUser('cookie-roundtrip@test.dev', 'Cookie Roundtrip')
    // The provider user id is the BA user id — the `baId` column for
    // engine-created models, not the Payload document id.
    const row = await baUserRow('cookie-roundtrip@test.dev')
    const baUserId = typeof row?.['baId'] === 'string' ? row['baId'] : null
    if (baUserId === null) {
      throw new Error('no ba-users row for the roundtrip user')
    }
    const createSession = engine.provider.createProviderSession
    if (createSession === undefined) {
      throw new Error('the better-auth provider cannot mint sessions')
    }
    const created = await createSession(baUserId, {
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    if (created.isErr()) {
      throw new Error(created.error.message)
    }
    const build = engine.provider.sessionCookie
    if (build === undefined) {
      throw new Error('the better-auth provider exposes no sessionCookie')
    }
    const setCookie = await build(created.value.token)
    // The signed form BA reads back with getSignedCookie: the raw
    // token alone resolves NO session (issue #72's original bug).
    const name = engine.sessionCookieNames[0] ?? ''
    expect(setCookie.startsWith(`${name}=${created.value.token}.`)).toBe(true)
    expect(setCookie).toContain('HttpOnly')
    expect(setCookie).toContain('SameSite=Lax')
    // The round trip: BA's own getSession resolves the user from our
    // cookie alone, with matching attributes from the real context.
    const session = await engine.auth.api.getSession({
      headers: new Headers({ cookie: setCookie }),
    })
    const user = (session as { user?: { email?: string } | null } | null)?.user
    expect(user?.email).toBe('cookie-roundtrip@test.dev')
    const sessionToken = (session as { session?: { token?: string } | null } | null)?.session?.token
    expect(sessionToken).toBe(created.value.token)
  })

  it('an unsigned cookie resolves no session', async () => {
    await signUpUser('unsigned-cookie@test.dev', ' Unsigned Cookie')
    const row = await baUserRow('unsigned-cookie@test.dev')
    const baUserId = typeof row?.['baId'] === 'string' ? row['baId'] : null
    if (baUserId === null) {
      throw new Error('no ba-users row for the unsigned-cookie user')
    }
    const createSession = engine.provider.createProviderSession
    if (createSession === undefined) {
      throw new Error('the better-auth provider cannot mint sessions')
    }
    const created = await createSession(baUserId, {
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    if (created.isErr()) {
      throw new Error(created.error.message)
    }
    const name = engine.sessionCookieNames[0] ?? ''
    const unsigned = await engine.auth.api.getSession({
      headers: new Headers({ cookie: `${name}=${created.value.token}` }),
    })
    expect(unsigned?.user ?? null).toBeNull()
  })
})

describe('user deletion', () => {
  it('removes provider rows but keeps the Payload user', async () => {
    const signedUp = await engine.auth.handler(
      authRequest('/sign-up/email', {
        method: 'POST',
        body: { name: 'Grace Hopper', email: 'grace@test.dev', password: 'correct-horse-battery' },
      })
    )
    expect(signedUp.status).toBe(200)
    const cookie = sessionCookieFrom(signedUp, engine.sessionCookieNames[0] ?? '')
    await verifyEmail('grace@test.dev')
    const bridged = await handleEndpoints({
      config,
      request: pluginRequest('/auth-link/session', cookie),
    })
    expect(bridged.status).toBe(200)

    const deleted = await engine.auth.handler(
      authRequest('/delete-user', {
        method: 'POST',
        body: { password: 'correct-horse-battery' },
        cookie,
      })
    )
    expect(deleted.status).toBe(200)
    const users = await payload.find({
      collection: 'ba-users',
      where: { email: { equals: 'grace@test.dev' } },
      limit: 1,
      overrideAccess: true,
    })
    expect(users.totalDocs).toBe(0)
    const kept = await payload.find({
      collection: 'users',
      where: { email: { equals: 'grace@test.dev' } },
      limit: 1,
      overrideAccess: true,
    })
    expect(kept.totalDocs).toBe(1)
  })
})
