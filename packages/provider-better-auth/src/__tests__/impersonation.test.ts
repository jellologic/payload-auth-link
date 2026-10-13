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
let impersonatedCookie = ''

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
