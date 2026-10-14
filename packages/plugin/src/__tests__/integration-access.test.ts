/**
 * Integration tests: injected-field access defaults over real Payload
 * request handling. A plain, verified,
 * self-registered user must not be able to grant themselves roles,
 * reach the admin panel, or read operator-facing fields — while the
 * Local API (overrideAccess) keeps working for the engine, and role
 * managers keep full REST access.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { parseEmail } from '@payload-auth-link/core'
import { authLink } from '../index.js'
import { wireOptions } from '../options.js'
import { createServices } from '../services.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'access-defaults-secret-32-chars!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

type Session = { jar: string; id: string; roles: string[] }

async function rest(
  method: string,
  path: string,
  opts: { jar?: string; body?: unknown } = {}
): Promise<{ status: number; body: unknown }> {
  // Same-origin headers on every method: Payload refuses the auth
  // token on requests whose Origin/Referer story does not match the
  // server URL, and this in-process harness sends what a browser
  // would.
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    origin: ORIGIN,
  }
  if (opts.jar !== undefined) {
    headers.cookie = opts.jar
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
  return { status: response.status, body }
}

function setCookieOf(responseHeaders: Headers): string {
  const setCookie = responseHeaders.get('set-cookie') ?? ''
  return setCookie.split(';')[0] ?? ''
}

async function loginAs(email: string, password: string): Promise<Session> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/users/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ email, password }),
    }),
  })
  expect(response.status).toBe(200)
  const body = (await response.json()) as { user: { id: string; roles: string[] } }
  return {
    jar: setCookieOf(response.headers),
    id: String(body.user.id),
    roles: body.user.roles,
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
    // The documented setup: no collection access declared.
    collections: [{ slug: 'users', auth: true, fields: [] }],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  await payload.create({
    collection: 'users',
    data: { email: 'admin@test.dev', password: 'correct-horse-battery', roles: ['admin'] },
  })
  await payload.create({
    collection: 'users',
    data: {
      email: 'plain@test.dev',
      password: 'correct-horse-battery',
      roles: ['user'],
      identities: [
        {
          providerId: 'stub',
          providerUserId: 'plain-1',
          email: 'plain@test.dev',
          linkedAt: new Date().toISOString(),
        },
      ],
      suspendedUntil: '2031-01-01T00:00:00.000Z',
      suspendReason: 'internal note: fraud investigation',
      linkable: true,
      linkableEmail: 'plain@test.dev',
    },
  })
  // Simulates a document created outside the plugin (pre-upgrade row,
  // or an attacker before the fix): no linkable marker.
  await payload.create({
    collection: 'users',
    data: {
      email: 'unproven@test.dev',
      password: 'AttackerKnows-1',
      roles: ['user'],
      linkable: false,
    },
  })
}, 60_000)

describe('injected field access defaults', () => {
  it('a plain user cannot grant themselves roles; the session stays ["user"]', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const attempt = await rest('PATCH', `/users/${session.id}`, {
      jar: session.jar,
      body: { roles: ['admin'] },
    })
    // Payload answers a field-access denial by stripping the field;
    // whatever the status, the write must not take effect.
    const body = attempt.body as { doc?: { roles?: string[] } }
    expect(body.doc?.roles).not.toEqual(['admin'])
    // A fresh login re-reads the stored document: still just `user`.
    const after = await loginAs('plain@test.dev', 'correct-horse-battery')
    expect(after.roles).toEqual(['user'])
  })

  it('a plain user holds no governing permissions on the users collection', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const access = await rest('GET', '/access', { jar: session.jar })
    // Payload 3.90's /api/access serves the per-collection permission
    // map; canAccessAdmin itself is served by the admin routes. The
    // governing signal here: the plain user gets NO permissions on
    // the injected roles field, and the collection update grant that
    // made the exploit possible does not extend to governing fields.
    const body = access.body as {
      collections: {
        users: { fields: Record<string, unknown>; update?: boolean }
      }
    }
    const fields = body.collections.users?.fields ?? {}
    expect(fields.roles).toBeUndefined()
    expect(fields.suspendReason).toBeUndefined()
  })

  it('operator-facing fields are stripped from every row a plain user reads', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const list = await rest('GET', '/users?depth=0&limit=10', { jar: session.jar })
    expect(list.status).toBe(200)
    const docs = (list.body as { docs: Array<Record<string, unknown>> }).docs
    expect(docs.length).toBeGreaterThan(0)
    for (const doc of docs) {
      expect(doc).not.toHaveProperty('suspendReason')
      expect(doc).not.toHaveProperty('suspendedUntil')
      // Payload strips read-denied arrays to an empty list: no row
      // content (provider ids, emails) may leak either way.
      const identities = doc.identities
      expect(
        identities === undefined || (Array.isArray(identities) && identities.length === 0)
      ).toBe(true)
    }
  })

  it('a plain user still reads their own roles', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const me = await rest('GET', `/users/${session.id}`, { jar: session.jar })
    const body = me.body as { roles?: string[] }
    expect(body.roles).toEqual(['user'])
  })

  it('a role manager keeps REST access: edit roles, read operator fields', async () => {
    const admin = await loginAs('admin@test.dev', 'correct-horse-battery')
    const access = await rest('GET', '/access', { jar: admin.jar })
    const fields = (access.body as { collections: { users: { fields: Record<string, unknown> } } })
      .collections.users.fields
    // The manager's permission map carries the governing grants the
    // plain user's map lacked (Payload collapses full field
    // permission to `true`).
    expect(fields.roles).toBe(true)

    const grant = await rest('PATCH', `/users/${admin.id}`, {
      jar: admin.jar,
      body: { roles: ['admin'] },
    })
    expect(grant.status).toBe(200)
    expect((grant.body as { doc: { roles: string[] } }).doc.roles).toEqual(['admin'])

    const list = await rest('GET', '/users?depth=0&limit=10', { jar: admin.jar })
    const docs = (list.body as { docs: Array<Record<string, unknown>> }).docs
    const plain = docs.find((doc) => doc.email === 'plain@test.dev')
    expect(plain?.suspendReason).toBe('internal note: fraud investigation')
    expect(Array.isArray(plain?.identities)).toBe(true)
  })

  it('the Local API (overrideAccess) is unaffected: the engine still links and governs', async () => {
    const plain = await payload.find({
      collection: 'users',
      where: { email: { equals: 'plain@test.dev' } },
      limit: 1,
      overrideAccess: true,
    })
    const id = plain.docs[0]?.id
    expect(id).toBeDefined()
    const updated = await payload.update({
      collection: 'users',
      id: id as string,
      data: { roles: ['admin'] },
      overrideAccess: true,
    })
    expect(updated.roles).toEqual(['admin'])
    // restore
    await payload.update({
      collection: 'users',
      id: id as string,
      data: { roles: ['user'] },
      overrideAccess: true,
    })
  })

  it('a non-manager cannot create users over REST (GHSA-98hq-hh6v-2p2r)', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const created = await rest('POST', '/users', {
      jar: session.jar,
      body: { email: 'victim@test.dev', password: 'AttackerKnows-1' },
    })
    expect(created.status).toBe(403)
  })

  it('a non-manager sees only their own document in the list', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const list = await rest('GET', '/users?depth=0&limit=10', { jar: session.jar })
    expect(list.status).toBe(200)
    const docs = (list.body as { docs: Array<Record<string, unknown>> }).docs
    expect(docs.length).toBe(1)
    expect(docs[0]?.email).toBe('plain@test.dev')
    void docs
  })

  it('an unproven pre-existing document is never JIT-linked', async () => {
    await loginAs('unproven@test.dev', 'AttackerKnows-1')
    const linked = stub.issue({
      sessionId: 'sess-unproven-link',
      providerUserId: 'unproven-identity',
      email: 'unproven@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await rest('GET', '/auth-link/session', { jar: linked })
    // The verified provider identity carries the same email as the
    // unproven document, yet the link is refused: no session.
    expect(response.status).toBe(401)
  })

  it('a proven (manager-created) document IS linked — migration path intact', async () => {
    const admin = await loginAs('admin@test.dev', 'correct-horse-battery')
    const created = await rest('POST', '/users', {
      jar: admin.jar,
      body: { email: 'proven@test.dev', password: 'ImportedKnows-1' },
    })
    expect(created.status).toBe(201)
    // The marker hook proved the manager-created document.
    const linked = stub.issue({
      sessionId: 'sess-proven-link',
      providerUserId: 'proven-identity',
      email: 'proven@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await rest('GET', '/auth-link/session', { jar: linked })
    expect(response.status).toBe(200)
    const body = response.body as { user: { email: string; id: string } }
    expect(body.user.email).toBe('proven@test.dev')
    const createdDoc = (created.body as { doc: { id: string } }).doc
    expect(body.user.id).toBe(String(createdDoc.id))
  })

  it('self-service email changes are stripped on linked documents (GHSA-8524)', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    const attempt = await rest('PATCH', `/users/${session.id}`, {
      jar: session.jar,
      body: { email: 'planted@test.dev' },
    })
    const body = attempt.body as { doc?: { email?: string } }
    // Stripped (200) or refused — either way the planted email does
    // not land on the document.
    expect(body.doc?.email ?? 'plain@test.dev').toBe('plain@test.dev')
  })

  it('self-service password changes are stripped; the planted password does not log in', async () => {
    const session = await loginAs('plain@test.dev', 'correct-horse-battery')
    await rest('PATCH', `/users/${session.id}`, {
      jar: session.jar,
      body: { password: 'AttackerKnows-9' },
    })
    const replant = await rest('POST', '/users/login', {
      body: { email: 'plain@test.dev', password: 'AttackerKnows-9' },
    })
    expect(replant.status).toBe(401)
    const still = await rest('POST', '/users/login', {
      body: { email: 'plain@test.dev', password: 'correct-horse-battery' },
    })
    expect(still.status).toBe(200)
  })

  it('the provider-email resync keeps the linkable proof bound (overrideAccess path)', async () => {
    const session = await loginAs('admin@test.dev', 'correct-horse-battery')
    // Manager withdraws the proof over REST...
    const withdraw = await rest('PATCH', `/users/${session.id}`, {
      jar: session.jar,
      body: { linkable: false, linkableEmail: '' },
    })
    expect(withdraw.status).toBe(200)
    // ...then the plugin's provider-email resync (repository setEmail,
    // Local API with overrideAccess) re-establishes it for the new
    // provider-verified address.
    const wired = wireOptions({
      baseUrl: ORIGIN,
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [stub.provider],
    })
    const { users: resyncUsers } = createServices(wired, payload)
    const changed = parseEmail('moved@test.dev')._unsafeUnwrap()
    const resynced = await resyncUsers.setEmail(
      session.id as unknown as Parameters<typeof resyncUsers.setEmail>[0],
      changed
    )
    expect(resynced.isOk()).toBe(true)
    const found = await payload.findByID({
      collection: 'users',
      id: session.id,
      overrideAccess: true,
    })
    expect(found.email).toBe('moved@test.dev')
    expect((found as unknown as { linkable: boolean }).linkable).toBe(true)
    expect((found as unknown as { linkableEmail: string }).linkableEmail).toBe('moved@test.dev')
  })

  it('config fails fast when no admin role exists and none is named', async () => {
    const { wireOptions } = await import('../options.js')
    expect(() =>
      wireOptions({
        baseUrl: ORIGIN,
        roles: ['owner', 'editor'],
        defaultRole: 'editor',
        providers: [stub.provider],
      })
    ).toThrow(/roleManagerRoles is required/)
    const wired = wireOptions({
      baseUrl: ORIGIN,
      roles: ['owner', 'editor'],
      defaultRole: 'editor',
      providers: [stub.provider],
      roleManagerRoles: ['owner'],
    })
    expect(wired.roleManagerRoles).toEqual(['owner'])
  })
})
