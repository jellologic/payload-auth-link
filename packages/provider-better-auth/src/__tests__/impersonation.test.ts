/**
 * Impersonation integration (CAP-8a): a real Better Auth engine with the
 * `admin` plugin on real Payload storage (SQLite in memory), bridged by
 * the auth-link plugin. Proves an impersonated session is distinguishable
 * (`ProviderSession.actor`), its use is audit-logged through
 * `LoggerPort`, and plugin logout expires BA's `admin_session` cookie
 * alongside the session token.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { LoggerPort } from '@payload-auth-link/core'
import { authLink } from '@payload-auth-link/plugin'
import { admin } from 'better-auth/plugins'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://impersonation.test'
const SECRET = 'impersonation-integration-secret!!'
const ADMIN_EMAIL = 'operator@impersonation.test'
const TARGET_EMAIL = 'target@impersonation.test'

const auditInfo = vi.fn()
const auditLogger: LoggerPort = {
  debug: vi.fn(),
  info: auditInfo,
  warn: vi.fn(),
  error: vi.fn(),
  child: () => auditLogger,
}

/** The durable audit sink (`onAudit`): what "audited" must survive. */
const auditEvents: { message: string; fields: Record<string, unknown> }[] = []

let config: SanitizedConfig
let latePayload: Payload | undefined
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  // The admin plugin's fields, mirrored exactly (see its schema).
  customFields: {
    user: [
      { name: 'role', type: 'text' },
      { name: 'banned', type: 'boolean' },
      { name: 'banReason', type: 'text' },
      { name: 'banExpires', type: 'date' },
    ],
    session: [{ name: 'impersonatedBy', type: 'text' }],
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    plugins: [admin()],
  },
})

function cookieHeaderFrom(response: Response): string {
  // Browser semantics: a later Set-Cookie for a name replaces the earlier
  // one (impersonation expires the old session token before setting the
  // new one, so both appear and only the last may be sent back).
  const jar = new Map<string, string>()
  for (const entry of response.headers.getSetCookie()) {
    const pair = entry.split(';', 1)[0]
    if (pair === undefined || pair === '') {
      continue
    }
    const name = pair.split('=', 1)[0]
    if (name !== undefined && name !== '') {
      jar.set(name, pair)
    }
  }
  return [...jar.values()].join('; ')
}

function authRequest(
  path: string,
  init: { method?: string; body?: unknown; cookie?: string } = {}
): Request {
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: init.method ?? 'GET',
    headers: {
      origin: ORIGIN,
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(init.cookie === undefined ? {} : { cookie: init.cookie }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  })
}

async function signUp(email: string, name: string): Promise<{ baUserId: string; cookie: string }> {
  const response = await engine.auth.handler(
    authRequest('/sign-up/email', {
      method: 'POST',
      body: { name, email, password: 'correct-horse-battery' },
    })
  )
  expect(response.status).toBe(200)
  const body = (await response.json()) as { user?: { id?: unknown } }
  if (typeof body.user?.id !== 'string') {
    throw new Error('sign-up returned no user id')
  }
  return { baUserId: body.user.id, cookie: cookieHeaderFrom(response) }
}

let payload: Payload
let adminBaUserId = ''
let targetBaUserId = ''
let adminCookie = ''
let targetCookie = ''
let impersonatedCookie = ''

async function rest(
  method: string,
  path: string,
  cookie: string,
  body?: unknown
): Promise<{ status: number; body: unknown }> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers: {
        cookie,
        origin: ORIGIN,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
  })
  let parsed: unknown
  try {
    parsed = await response.json()
  } catch {
    parsed = null
  }
  return { status: response.status, body: parsed }
}

async function hostDoc(email: string): Promise<Record<string, unknown>> {
  const found = await payload.find({
    collection: 'users',
    where: { email: { equals: email } },
    limit: 1,
    depth: 0,
    overrideAccess: true,
  })
  const doc = found.docs[0]
  if (doc === undefined) {
    throw new Error(`no host user ${email}`)
  }
  return doc
}

async function canAccessAdmin(cookie: string): Promise<unknown> {
  const access = await rest('GET', '/access', cookie)
  expect(access.status).toBe(200)
  return (access.body as { canAccessAdmin?: unknown }).canAccessAdmin
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
        logger: auditLogger,
        onAudit: (event) => {
          auditEvents.push(event)
        },
      }),
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context

  const operator = await signUp(ADMIN_EMAIL, 'Operator')
  adminBaUserId = operator.baUserId
  adminCookie = operator.cookie
  const target = await signUp(TARGET_EMAIL, 'Target')
  targetBaUserId = target.baUserId
  targetCookie = target.cookie

  // BA-side operator role + verified emails (the plugin JIT gate reads
  // the verified flag; BA's admin middleware reads the role).
  await payload.update({
    collection: 'ba-users',
    where: { email: { equals: ADMIN_EMAIL } },
    data: { role: 'admin', emailVerified: true },
    overrideAccess: true,
  })
  await payload.update({
    collection: 'ba-users',
    where: { email: { equals: TARGET_EMAIL } },
    data: { emailVerified: true },
    overrideAccess: true,
  })

  const impersonation = await engine.auth.handler(
    authRequest('/admin/impersonate-user', {
      method: 'POST',
      body: { userId: targetBaUserId },
      cookie: adminCookie,
    })
  )
  expect(impersonation.status).toBe(200)
  impersonatedCookie = cookieHeaderFrom(impersonation)
  expect(impersonatedCookie).toContain('better-auth.admin_session=')
}, 120_000)

describe('impersonated provider session (CAP-8a)', () => {
  it('is distinguishable through the port: actor set, plain session actor null', async () => {
    const impersonated = await engine.provider.getSession(
      new Headers({ cookie: impersonatedCookie })
    )
    expect(impersonated.isOk()).toBe(true)
    if (impersonated.isOk()) {
      expect(impersonated.value?.providerUserId).toBe(targetBaUserId)
      expect(impersonated.value?.actor).toEqual({ providerUserId: adminBaUserId })
    }
    const own = await engine.provider.getSession(new Headers({ cookie: adminCookie }))
    expect(own.isOk()).toBe(true)
    if (own.isOk()) {
      expect(own.value?.providerUserId).toBe(adminBaUserId)
      expect(own.value?.actor).toBeNull()
    }
  })

  it('audit-logs actor and target when the plugin session endpoint is used', async () => {
    auditInfo.mockClear()
    const response = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        headers: { cookie: impersonatedCookie },
      }),
    })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { id: unknown; email: string } }
    expect(body.user.email).toBe(TARGET_EMAIL)
    expect(auditInfo).toHaveBeenCalledWith(
      'impersonated session used',
      expect.objectContaining({
        providerId: 'better-auth',
        actorProviderUserId: adminBaUserId,
        targetProviderUserId: targetBaUserId,
        targetUserId: String(body.user.id),
      })
    )
  })

  // Matrix row 15, deny half, on the real engine: the target is a role
  // manager, so every refusal below is the impersonation policy — the
  // target's OWN session makes the identical requests succeed.
  it('denies admin-panel access and role / email writes while impersonating (real BA)', async () => {
    const target = await hostDoc(TARGET_EMAIL)
    const targetId = String(target.id)
    await payload.update({
      collection: 'users',
      id: targetId,
      data: { roles: ['admin'] },
      overrideAccess: true,
    })
    const bystander = await payload.create({
      collection: 'users',
      data: { email: 'bystander@impersonation.test', password: 'unused-1', roles: ['user'] },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    const bystanderId = String(bystander.id)

    // Control: the target's own session is a role manager.
    expect(await canAccessAdmin(targetCookie)).toBe(true)
    // Impersonated: no admin panel.
    expect(await canAccessAdmin(impersonatedCookie)).toBeFalsy()

    // A role write under impersonation never lands.
    const roleWrite = await rest('PATCH', `/users/${bystanderId}`, impersonatedCookie, {
      roles: ['admin'],
    })
    expect(roleWrite.status).toBe(403)
    expect((await hostDoc('bystander@impersonation.test')).roles).toEqual(['user'])
    // An email write under impersonation never lands (own doc included).
    const emailWrite = await rest('PATCH', `/users/${targetId}`, impersonatedCookie, {
      email: 'hijacked@impersonation.test',
    })
    expect(emailWrite.status).toBe(403)
    expect((await hostDoc(TARGET_EMAIL)).email).toBe(TARGET_EMAIL)

    // Control: the identical role write under the target's own session lands.
    const plain = await rest('PATCH', `/users/${bystanderId}`, targetCookie, { roles: ['admin'] })
    expect(plain.status).toBe(200)
    expect((await hostDoc('bystander@impersonation.test')).roles).toEqual(['admin'])
  })

  // Matrix row 15, audit half: every collection operation under the
  // impersonated session reaches BOTH the logger and the durable
  // `onAudit` sink with the real BA actor; plain sessions audit nothing.
  it('audits impersonated collection operations to logger AND onAudit (real BA)', async () => {
    const targetId = String((await hostDoc(TARGET_EMAIL)).id)
    auditInfo.mockClear()
    auditEvents.length = 0
    const read = await rest('GET', `/users/${targetId}`, impersonatedCookie)
    expect(read.status).toBe(200)
    const expected = expect.objectContaining({
      actorProviderUserId: adminBaUserId,
      targetUserId: targetId,
      collection: 'users',
      id: targetId,
    }) as unknown
    expect(auditInfo).toHaveBeenCalledWith('impersonated operation', expected)
    expect(auditEvents).toContainEqual({ message: 'impersonated operation', fields: expected })

    // A refused write is audited too (beforeOperation runs before access).
    auditEvents.length = 0
    const refused = await rest('PATCH', `/users/${targetId}`, impersonatedCookie, {
      roles: ['user'],
    })
    expect(refused.status).toBe(403)
    expect(auditEvents).toContainEqual({
      message: 'impersonated operation',
      fields: expect.objectContaining({
        actorProviderUserId: adminBaUserId,
        operation: 'update',
        collection: 'users',
      }) as unknown,
    })

    // The target's own session is not impersonated: no audit line.
    auditEvents.length = 0
    expect((await rest('GET', `/users/${targetId}`, targetCookie)).status).toBe(200)
    expect(auditEvents.some((event) => event.message === 'impersonated operation')).toBe(false)
  })

  it('expires the admin_session cookie (and the session token) on plugin logout', async () => {
    const response = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        method: 'DELETE',
        headers: { cookie: impersonatedCookie, 'x-auth-link-csrf': '1' },
      }),
    })
    expect(response.status).toBe(200)
    const cleared = response.headers.getSetCookie()
    expect(cleared).toContain('better-auth.session_token=; Max-Age=0; Path=/')
    expect(cleared).toContain('better-auth.admin_session=; Max-Age=0; Path=/')
  })
})

// Runs last: suspending the target revokes every session it holds,
// impersonated ones included.
describe('admin endpoints hand page JavaScript no session token (issue #116, real BA)', () => {
  /** The raw session token inside a cookie header's signed session cookie. */
  function rawTokenOf(cookie: string): string {
    const pair = cookie.split('; ').find((entry) => entry.startsWith('better-auth.session_token='))
    if (pair === undefined) {
      throw new Error('no session cookie')
    }
    const value = decodeURIComponent(pair.slice(pair.indexOf('=') + 1))
    return value.slice(0, value.lastIndexOf('.'))
  }

  async function freshAdminCookie(): Promise<string> {
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: ADMIN_EMAIL, password: 'correct-horse-battery' },
      })
    )
    expect(signIn.status).toBe(200)
    return cookieHeaderFrom(signIn)
  }

  it('/admin/list-user-sessions lists the target sessions without their tokens', async () => {
    const listed = await engine.auth.handler(
      authRequest('/admin/list-user-sessions', {
        method: 'POST',
        body: { userId: targetBaUserId },
        cookie: await freshAdminCookie(),
      })
    )
    expect(listed.status).toBe(200)
    const text = await listed.text()
    const sessions = (JSON.parse(text) as { sessions: Record<string, unknown>[] }).sessions
    expect(sessions.length).toBeGreaterThanOrEqual(1)
    for (const session of sessions) {
      expect(session.id).toEqual(expect.any(String))
      expect(session.userId).toBe(targetBaUserId)
      expect(session).not.toHaveProperty('token')
    }
    expect(text).not.toContain(rawTokenOf(targetCookie))
  })

  it('/admin/impersonate-user answers without the impersonation session token', async () => {
    const impersonation = await engine.auth.handler(
      authRequest('/admin/impersonate-user', {
        method: 'POST',
        body: { userId: targetBaUserId },
        cookie: await freshAdminCookie(),
      })
    )
    expect(impersonation.status).toBe(200)
    const text = await impersonation.text()
    const body = JSON.parse(text) as { session?: Record<string, unknown> }
    expect(body.session?.userId).toBe(targetBaUserId)
    expect(body.session).not.toHaveProperty('token')
    expect(text).not.toContain(rawTokenOf(cookieHeaderFrom(impersonation)))
  })
})

describe('impersonated session of a suspended target (row 15, real BA)', () => {
  it('a fresh impersonation is refused once the TARGET is suspended', async () => {
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: ADMIN_EMAIL, password: 'correct-horse-battery' },
      })
    )
    expect(signIn.status).toBe(200)
    const impersonation = await engine.auth.handler(
      authRequest('/admin/impersonate-user', {
        method: 'POST',
        body: { userId: targetBaUserId },
        cookie: cookieHeaderFrom(signIn),
      })
    )
    expect(impersonation.status).toBe(200)
    const cookie = cookieHeaderFrom(impersonation)
    expect((await rest('GET', '/auth-link/session', cookie)).status).toBe(200)
    const targetId = String((await hostDoc(TARGET_EMAIL)).id)
    expect((await rest('GET', `/users/${targetId}`, cookie)).status).toBe(200)

    await payload.update({
      collection: 'users',
      id: targetId,
      data: { suspendedUntil: '2031-01-01T00:00:00.000Z' },
      overrideAccess: true,
    })
    expect((await rest('GET', '/auth-link/session', cookie)).status).toBe(401)
    expect((await rest('GET', `/users/${targetId}`, cookie)).status).toBe(403)
  })
})
