/**
 * Integration test: GHSA-gw3c-8g59-q72j — Payload's admin **Log out**
 * (`POST /api/<users>/logout`) ends only Payload's own token; the
 * provider's session cookie stayed live, so the next request was still
 * authenticated as the same user. Driven through `handleEndpoints`
 * against real Payload on SQLite with the stub provider issuing
 * sessions: the users collection' afterLogout hook must revoke the
 * presented provider session and expire every provider session cookie
 * — and leave a Payload-local-only logout untouched. Both users
 * collection assembly paths are exercised (a host-declared collection
 * the plugin adopts, and one the plugin creates).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { defineProviderId, nullLogger } from '@payload-auth-link/core'
import type { IdentityProviderPort } from '@payload-auth-link/core'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import type { AuthLinkPluginOptions } from '../options.js'
import { createStubProvider, stubCookieName } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'admin-logout-secret-32-chars!!'

const dir = mkdtempSync(join(tmpdir(), 'pal-admin-logout-'))
const stubAdopted = createStubProvider()
const stubCreated = createStubProvider()
const stubSecure = createStubProvider()

const inOneHour = (): Date => new Date(Date.now() + 3_600_000)

function optionsWith(providers: readonly IdentityProviderPort[]): AuthLinkPluginOptions {
  return {
    baseUrl: ORIGIN,
    roles: ['admin', 'user'],
    defaultRole: 'user',
    roleManagerRoles: ['admin'],
    providers: [...providers],
    logger: nullLogger(),
  }
}

/**
 * The secure-cookie variant of the stub: the same session store under a
 * `__Secure-` cookie name with provider-declared clearing attributes
 * (what Better Auth reports for its `__Secure-` sessions), plus a
 * non-session logout cookie.
 */
const secureCookieName = '__Secure-al_stub_session'
const secureProvider: IdentityProviderPort = {
  ...stubSecure.provider,
  id: defineProviderId('stub-secure'),
  sessionCookieNames: [secureCookieName],
  logoutCookieNames: ['al_admin_session'],
  sessionCookieClearOptions: (name: string) =>
    name === secureCookieName
      ? { maxAge: 0, path: '/', secure: true, sameSite: 'lax', httpOnly: true }
      : undefined,
  getSession: (headers) => {
    // The underlying stub store keys sessions by its own cookie name;
    // the wrapper presents them under the `__Secure-` name.
    const cookie = headers.get('cookie') ?? ''
    const rewritten = cookie.replaceAll(`${secureCookieName}=`, `${stubCookieName}=`)
    return stubSecure.provider.getSession(new Headers({ cookie: rewritten }))
  },
}

type Instance = {
  readonly key: string
  readonly config: SanitizedConfig
  readonly payload: Payload
}

async function boot(
  key: string,
  providers: readonly IdentityProviderPort[],
  hostUsersCollection: boolean
): Promise<Instance> {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    // One shared SQLite file: sequential Payload instances in one
    // process each run push (the pattern the server-sessions suite
    // uses for multi-boot files).
    db: sqliteAdapter({ client: { url: `file:${join(dir, 'shared.db')}` }, push: true }),
    collections: hostUsersCollection
      ? [
          {
            slug: 'users',
            auth: true,
            fields: [{ name: 'email', type: 'email', required: true, index: true }],
          },
        ]
      : [{ slug: 'pages', fields: [{ name: 'title', type: 'text' }] }],
    plugins: [authLink(optionsWith(providers))],
  })
  const payload = await getPayload({ config, key })
  return { key, config, payload }
}

type Reply = {
  readonly status: number
  readonly body: unknown
  readonly cookies: readonly string[]
}

async function rest(
  instance: Instance,
  method: string,
  path: string,
  opts: { jar?: string; body?: unknown } = {}
): Promise<Reply> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    origin: ORIGIN,
  }
  if (opts.jar !== undefined) {
    headers.cookie = opts.jar
  }
  const response = await handleEndpoints({
    config: instance.config,
    payloadInstanceCacheKey: instance.key,
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
  return { status: response.status, body, cookies: response.headers.getSetCookie() }
}

/**
 * A linked document. A local password is required on the ADOPTED
 * collection (Payload registers every create on an auth collection
 * without `disableLocalStrategy` through the local strategy), and
 * unnecessary on the plugin-created one (`optionalPassword`) — pass it
 * only where the schema wants it.
 */
async function seedLinked(
  instance: Instance,
  email: string,
  providerId: string,
  providerUserId: string,
  password?: string
): Promise<void> {
  await instance.payload.create({
    collection: 'users',
    overrideAccess: true,
    data: {
      email,
      roles: ['user'],
      ...(password === undefined ? {} : { password }),
      identities: [{ providerId, providerUserId, email, linkedAt: new Date().toISOString() }],
    },
  })
}

async function seedLocal(instance: Instance, email: string): Promise<void> {
  await instance.payload.create({
    collection: 'users',
    overrideAccess: true,
    data: { email, password: 'correct-horse-battery', roles: ['user'] },
  })
}

/** The `payload-token` cookie of a fresh local login, or a failed test. */
async function localJar(instance: Instance, email: string): Promise<string> {
  const login = await rest(instance, 'POST', '/users/login', {
    body: { email, password: 'correct-horse-battery' },
  })
  expect(login.status).toBe(200)
  const token = login.cookies.find((cookie) => cookie.startsWith('payload-token='))
  if (token === undefined) {
    throw new Error('local login issued no payload-token cookie')
  }
  return token.split(';')[0] ?? ''
}

/** The provider-session jar for one issued stub session, renamed when the provider presents it under another name. */
function providerJar(stub: ReturnType<typeof createStubProvider>, sessionId: string): string {
  const issued = stub.issue({
    sessionId,
    providerUserId: `p-${sessionId}`,
    email: `${sessionId}@test.dev`,
    expiresAt: inOneHour(),
  })
  if (!issued.startsWith(`${stubCookieName}=`)) {
    throw new Error('unexpected stub cookie name')
  }
  if (stub === stubSecure) {
    return issued.replace(`${stubCookieName}=`, `${secureCookieName}=`)
  }
  return issued
}

afterAll(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('admin logout ends the provider session (GHSA-gw3c-8g59-q72j)', () => {
  describe('adopted users collection', () => {
    let instance: Instance
    beforeAll(async () => {
      instance = await boot('logout-adopted', [stubAdopted.provider], true)
    }, 120_000)

    it('Log out revokes the provider session and expires its cookie', async () => {
      const jar = providerJar(stubAdopted, 'sess-admin-logout')
      await seedLinked(
        instance,
        'sess-admin-logout@test.dev',
        'stub',
        'p-sess-admin-logout',
        'correct-horse-battery'
      )
      const pre = await rest(instance, 'GET', '/auth-link/session', { jar })
      expect(pre.status).toBe(200)

      const out = await rest(instance, 'POST', '/users/logout', { jar })
      expect(out.status).toBe(200)
      const clears = out.cookies.filter((cookie) => cookie.startsWith(`${stubCookieName}=`))
      expect(clears).toHaveLength(1)
      expect(clears[0]).toContain('Max-Age=0')
      expect(clears[0]).toContain('Path=/')

      // The provider session is gone server-side: the same jar no
      // longer resolves anywhere.
      expect(stubAdopted.sessions.has('sess-admin-logout')).toBe(false)
      const after = await rest(instance, 'GET', '/auth-link/session', { jar })
      expect(after.status).toBe(401)
    })

    it('a Payload-local-only logout is untouched', async () => {
      await seedLocal(instance, 'local-only@test.dev')
      const jar = await localJar(instance, 'local-only@test.dev')
      // An unrelated provider session is nobody's logout target: it
      // must stay live and its cookie must not be expired.
      const bystander = 'sess-bystander'
      stubAdopted.issue({
        sessionId: bystander,
        providerUserId: 'p-bystander',
        email: 'bystander@test.dev',
        expiresAt: inOneHour(),
      })

      const out = await rest(instance, 'POST', '/users/logout', { jar })
      expect(out.status).toBe(200)
      expect(out.cookies.some((cookie) => cookie.startsWith(`${stubCookieName}=`))).toBe(false)
      expect(stubAdopted.sessions.has(bystander)).toBe(true)
    })

    it('a stale provider cookie beside a local session is swept off the response', async () => {
      await seedLocal(instance, 'local-mixed@test.dev')
      const local = await localJar(instance, 'local-mixed@test.dev')
      // A dead provider cookie the strategy cannot verify: still
      // presented, so the logout response expires it (nothing live to
      // revoke).
      const jar = `${local}; ${stubCookieName}=sess-long-gone`

      const out = await rest(instance, 'POST', '/users/logout', { jar })
      expect(out.status).toBe(200)
      const clears = out.cookies.filter((cookie) => cookie.startsWith(`${stubCookieName}=`))
      expect(clears).toHaveLength(1)
      expect(clears[0]).toContain('Max-Age=0')
    })
  })

  describe('provider clearing attributes (`__Secure-` name, logout cookies)', () => {
    let instance: Instance
    beforeAll(async () => {
      instance = await boot('logout-secure', [secureProvider], true)
    }, 120_000)

    it('the clearing write keeps the live attributes; logout cookies expire too', async () => {
      const jar = providerJar(stubSecure, 'sess-secure-logout')
      await seedLinked(
        instance,
        'sess-secure-logout@test.dev',
        'stub-secure',
        'p-sess-secure-logout',
        'correct-horse-battery'
      )
      const pre = await rest(instance, 'GET', '/auth-link/session', { jar })
      expect(pre.status).toBe(200)

      const out = await rest(instance, 'POST', '/users/logout', { jar })
      expect(out.status).toBe(200)
      // A `__Secure-` cookie survives a clearing write without
      // `Secure` — the provider-reported attributes ride the expire.
      expect(out.cookies).toContainEqual(
        `${secureCookieName}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
      )
      // The non-session logout cookie expires as well.
      expect(out.cookies).toContainEqual('al_admin_session=; Max-Age=0; Path=/')
      expect(stubSecure.sessions.has('sess-secure-logout')).toBe(false)
    })
  })

  describe('plugin-created users collection', () => {
    let instance: Instance
    beforeAll(async () => {
      instance = await boot('logout-created', [stubCreated.provider], false)
    }, 120_000)

    it('the same hook rides the created collection', async () => {
      const jar = providerJar(stubCreated, 'sess-created-logout')
      await seedLinked(instance, 'sess-created-logout@test.dev', 'stub', 'p-sess-created-logout')
      const pre = await rest(instance, 'GET', '/auth-link/session', { jar })
      expect(pre.status).toBe(200)

      const out = await rest(instance, 'POST', '/users/logout', { jar })
      expect(out.status).toBe(200)
      const clears = out.cookies.filter((cookie) => cookie.startsWith(`${stubCookieName}=`))
      expect(clears).toHaveLength(1)
      expect(clears[0]).toContain('Max-Age=0')
      expect(stubCreated.sessions.has('sess-created-logout')).toBe(false)
    })
  })
})
