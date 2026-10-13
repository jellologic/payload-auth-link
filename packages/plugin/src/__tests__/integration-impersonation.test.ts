/**
 * Integration tests for CAP-13a (channel admission) and CAP-8b
 * (impersonation completed): a real Payload (SQLite in memory) with
 * the plugin, driven through `handleEndpoints` and the Local API.
 *
 * Security proofs, each of which fails without its fix: a bearer
 * session is refused by the default cookie-only policy, an
 * impersonated request cannot change roles or enter the admin
 * panel, and every impersonated Payload operation is audit-logged.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { LogFields, LoggerPort } from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type PayloadRequest,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'impersonation-secret-32-chars-min'

type LogCall = { readonly message: string; readonly fields: LogFields | undefined }

const infoCalls: LogCall[] = []
const warnCalls: LogCall[] = []

const capturingLogger: LoggerPort = {
  debug: () => undefined,
  info: (message, fields) => {
    infoCalls.push({ message, fields })
  },
  warn: (message, fields) => {
    warnCalls.push({ message, fields })
  },
  error: () => undefined,
  child: () => capturingLogger,
}

let config: SanitizedConfig
let payload: Payload
let operatorId: string | number
let targetId: string | number
let postId: string | number
const stub = createStubProvider()

function call(method: string, path: string, opts: { cookie?: string; csrf?: boolean } = {}) {
  const headers: Record<string, string> = {}
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.csrf === true) {
    headers['x-auth-link-csrf'] = '1'
  }
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, { method, headers }),
  })
}

/** The `req.user` shape the auth strategy produces for the target. */
function targetUser(actor: unknown) {
  return {
    id: String(targetId),
    collection: 'users',
    email: 'target@test.dev',
    roles: ['user'],
    ...(actor === undefined ? {} : { actor }),
  }
}

const resolvedActor = () => ({
  kind: 'payload-user',
  providerUserId: 'stub-operator',
  userId: String(operatorId),
})

async function seedUser(
  email: string,
  providerUserId: string,
  roles: string[]
): Promise<string | number> {
  const created = await payload.create({
    collection: 'users',
    data: {
      email,
      password: 'correct-horse-battery',
      roles,
      identities: [
        {
          providerId: 'stub',
          providerUserId,
          email,
          linkedAt: new Date().toISOString(),
        },
      ],
    },
  })
  return created.id
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      { slug: 'users', auth: true, fields: [] },
      { slug: 'posts', fields: [{ name: 'title', type: 'text' }] },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        logger: capturingLogger,
      }),
    ],
  })
  payload = await getPayload({ config })
  operatorId = await seedUser('operator@test.dev', 'stub-operator', ['admin'])
  targetId = await seedUser('target@test.dev', 'stub-target', ['user'])
  const post = await payload.create({ collection: 'posts', data: { title: 'hello' } })
  postId = post.id
}, 60_000)

describe('channel admission (CAP-13a)', () => {
  it('refuses a bearer-channel session by default (401) while cookie passes', async () => {
    const bearerCookie = stub.issue({
      sessionId: 'sess-bearer',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      channel: 'bearer',
    })
    expect((await call('GET', '/auth-link/session', { cookie: bearerCookie })).status).toBe(401)
    expect(
      warnCalls.some(
        (entry) =>
          entry.message === 'provider session channel not admitted' &&
          entry.fields?.channel === 'bearer'
      )
    ).toBe(true)

    const cookieCookie = stub.issue({
      sessionId: 'sess-cookie',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    expect((await call('GET', '/auth-link/session', { cookie: cookieCookie })).status).toBe(200)
  })

  it('keeps CSRF mandatory on logout regardless of channel', async () => {
    const bearerCookie = stub.issue({
      sessionId: 'sess-bearer-csrf',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      channel: 'bearer',
    })
    // No CSRF proof: refused before session handling even starts —
    // channel admission never became a CSRF exemption (CAP-13b).
    expect((await call('DELETE', '/auth-link/session', { cookie: bearerCookie })).status).toBe(403)
  })
})

describe('actor resolution and audit (CAP-8b)', () => {
  it("resolves Session.actor to the operator's Payload user id", async () => {
    const cookie = stub.issue({
      sessionId: 'sess-impersonated',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      actorProviderUserId: 'stub-operator',
    })
    const response = await call('GET', '/auth-link/session', { cookie })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { actor?: unknown } }
    expect(body.user.actor).toEqual({
      kind: 'payload-user',
      providerUserId: 'stub-operator',
      userId: String(operatorId),
    })
  })

  it('keeps an unlinked operator in distinct provider-only form with a warning', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-impersonated-ghost',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      actorProviderUserId: 'stub-ghost',
    })
    const response = await call('GET', '/auth-link/session', { cookie })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { actor?: unknown } }
    expect(body.user.actor).toEqual({
      kind: 'provider-only',
      providerUserId: 'stub-ghost',
    })
    expect(
      warnCalls.some(
        (entry) =>
          entry.message === 'impersonated session actor has no linked Payload user' &&
          entry.fields?.actorProviderUserId === 'stub-ghost'
      )
    ).toBe(true)
  })

  it('audit-logs every authenticated Payload operation while impersonating', async () => {
    const before = infoCalls.length
    const found = await payload.find({
      collection: 'posts',
      user: targetUser(resolvedActor()),
      overrideAccess: false,
    })
    expect(found.totalDocs).toBe(1)
    const one = await payload.findByID({
      collection: 'posts',
      id: postId,
      user: targetUser(resolvedActor()),
      overrideAccess: false,
    })
    expect(one.title).toBe('hello')
    const audited = infoCalls
      .slice(before)
      .filter((entry) => entry.message === 'impersonated operation')
    expect(audited).toEqual([
      {
        message: 'impersonated operation',
        fields: {
          actorProviderUserId: 'stub-operator',
          actorKind: 'payload-user',
          actorUserId: String(operatorId),
          targetUserId: String(targetId),
          // Payload reports Local API `find` to hooks as `read`.
          operation: 'read',
          collection: 'posts',
        },
      },
      {
        message: 'impersonated operation',
        fields: {
          actorProviderUserId: 'stub-operator',
          actorKind: 'payload-user',
          actorUserId: String(operatorId),
          targetUserId: String(targetId),
          operation: expect.any(String) as unknown,
          collection: 'posts',
          id: String(postId),
        },
      },
    ])
  })

  it('does not audit-log plain (non-impersonated) operations', async () => {
    const before = infoCalls.length
    await payload.find({
      collection: 'posts',
      user: targetUser(undefined),
      overrideAccess: false,
    })
    expect(
      infoCalls.slice(before).some((entry) => entry.message === 'impersonated operation')
    ).toBe(false)
  })
})

describe('real Payload auth path (strategy -> req.user)', () => {
  it('actor survives payload.auth and denies admin + role writes for that user', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-real-auth',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      actorProviderUserId: 'stub-operator',
    })
    // Payload's actual auth operation runs the registered strategies
    // (the same path REST requests take) — no hand-built `user:`.
    const authed = await payload.auth({ headers: new Headers({ cookie }) })
    expect(authed.user).not.toBeNull()
    const authUser = authed.user as unknown as { actor?: unknown }
    expect(authUser.actor).toEqual({
      kind: 'payload-user',
      providerUserId: 'stub-operator',
      userId: String(operatorId),
    })
    if (authed.user === null) {
      throw new Error('expected an authenticated user')
    }
    // The user object Payload itself produced must hit the denies.
    const admin = payload.collections.users?.config.access?.admin
    if (admin === undefined) {
      throw new Error('users admin access missing')
    }
    const req = { user: authed.user } as unknown as PayloadRequest
    await expect(admin({ req })).resolves.toBe(false)
    await payload
      .update({
        collection: 'users',
        id: targetId,
        data: { roles: ['admin'] },
        user: authed.user,
        overrideAccess: false,
      })
      .catch(() => undefined)
    const after = await payload.findByID({ collection: 'users', id: targetId })
    expect(after.roles).toEqual(['user'])
  })

  it('actor survives a real REST request (handleEndpoints) and role writes stay denied', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-real-rest',
      providerUserId: 'stub-target',
      email: 'target@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      actorProviderUserId: 'stub-operator',
    })
    const me = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/users/me`, {
        method: 'GET',
        headers: { cookie },
      }),
    })
    expect(me.status).toBe(200)
    const patch = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/users/${String(targetId)}`, {
        method: 'PATCH',
        headers: { cookie, 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({ roles: ['admin'] }),
      }),
    })
    // Denied or field-stripped: either way the stored roles must not move.
    expect([200, 400, 401, 403]).toContain(patch.status)
    const after = await payload.findByID({ collection: 'users', id: targetId })
    expect(after.roles).toEqual(['user'])

    // Control 1: a plain session can no longer
    // move roles at all — that write is role-manager-only now.
    await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/users/${String(targetId)}`, {
        method: 'PATCH',
        headers: {
          cookie: stub.issue({
            sessionId: 'sess-real-rest-plain',
            providerUserId: 'stub-target',
            email: 'target@test.dev',
            expiresAt: new Date(Date.now() + 3600_000),
          }),
          'content-type': 'application/json',
          origin: ORIGIN,
        },
        body: JSON.stringify({ roles: ['admin'] }),
      }),
    })
    const stripped = await payload.findByID({ collection: 'users', id: targetId })
    expect(stripped.roles).toEqual(['user'])

    // Control 2: the identical REST PATCH under the OPERATOR's session
    // (role manager, no actor) DOES move the roles — so the deny above
    // is the impersonation policy on the real `req.user`, not CSRF or
    // generic access. Reset afterwards for the suites below.
    const managerCookie = stub.issue({
      sessionId: 'sess-real-rest-manager',
      providerUserId: 'stub-operator',
      email: 'operator@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const managerPatch = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/users/${String(targetId)}`, {
        method: 'PATCH',
        headers: { cookie: managerCookie, 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({ roles: ['admin'] }),
      }),
    })
    expect(managerPatch.status).toBe(200)
    const promoted = await payload.findByID({ collection: 'users', id: targetId })
    expect(promoted.roles).toEqual(['admin'])
    await payload.update({ collection: 'users', id: targetId, data: { roles: ['user'] } })
  })
})

describe('impersonation restrictions (CAP-8b / D5)', () => {
  it('denies role changes while impersonating; the same write succeeds plainly', async () => {
    // Impersonated attempt to promote the target to admin. Field
    // access may reject the whole update or strip the field —
    // either way the stored roles must not move.
    await payload
      .update({
        collection: 'users',
        id: targetId,
        data: { roles: ['admin'] },
        user: targetUser(resolvedActor()),
        overrideAccess: false,
      })
      .catch(() => undefined)
    const afterAttempt = await payload.findByID({ collection: 'users', id: targetId })
    expect(afterAttempt.roles).toEqual(['user'])

    // Control: without an actor, the identical write under a
    // role-manager user goes through, proving the deny above is the
    // impersonation policy at work (a plain user would be denied by
    // the role-manager rule instead).
    const promoted = await payload.update({
      collection: 'users',
      id: targetId,
      data: { roles: ['admin'] },
      user: {
        id: String(operatorId),
        collection: 'users',
        email: 'operator@test.dev',
        roles: ['admin'],
      },
      overrideAccess: false,
    })
    expect(promoted.roles).toEqual(['admin'])
    await payload.update({
      collection: 'users',
      id: targetId,
      data: { roles: ['user'] },
      user: targetUser(undefined),
      overrideAccess: false,
    })
  })

  it('denies admin-panel access while impersonating', async () => {
    const admin = payload.collections.users?.config.access?.admin
    expect(admin).toBeTypeOf('function')
    if (admin === undefined) {
      throw new Error('users admin access missing')
    }
    const impersonatedReq = { user: targetUser(resolvedActor()) } as unknown as PayloadRequest
    const managerReq = {
      user: { ...targetUser(undefined), roles: ['admin'] },
    } as unknown as PayloadRequest
    const plainReq = { user: targetUser(undefined) } as unknown as PayloadRequest
    await expect(admin({ req: impersonatedReq })).resolves.toBe(false)
    // security hardening: the default admin-panel grant is the
    // role-manager roles, not "any signed-in user".
    await expect(admin({ req: managerReq })).resolves.toBe(true)
    await expect(admin({ req: plainReq })).resolves.toBe(false)
  })
})
