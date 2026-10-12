/**
 * Integration tests: a real Payload (SQLite in memory) with the plugin,
 * driven through Payload's own request handling (`handleEndpoints`).
 * Covers the merge path (existing users collection with local auth).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { errAsync } from 'neverthrow'
import {
  defineProviderId,
  parseEmail,
  parseRole,
  ProviderError,
  type Email,
  type IdentityProviderPort,
  type Role,
} from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type PayloadRequest,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createEndpoints } from '../endpoints.js'
import { authLink } from '../index.js'
import { wireOptions } from '../options.js'
import { createPayloadUserRepository } from '../repository.js'
import { createStubProvider, stubCookieName } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'integration-secret-32-chars-min!!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

function email(value: string): Email {
  const parsed = parseEmail(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

function role(value: string): Role {
  const parsed = parseRole(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

function call(
  method: string,
  path: string,
  opts: { cookie?: string; origin?: string | null; csrf?: boolean } = {}
) {
  const headers: Record<string, string> = {}
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.origin !== undefined && opts.origin !== null) {
    headers.origin = opts.origin
  }
  if (opts.csrf === true) {
    headers['x-auth-link-csrf'] = '1'
  }
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, { method, headers }),
  })
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
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
    data: {
      email: 'linked@test.dev',
      password: 'correct-horse-battery',
      roles: ['admin'],
      identities: [
        {
          providerId: 'stub',
          providerUserId: 'stub-linked',
          email: 'linked@test.dev',
          linkedAt: new Date().toISOString(),
        },
      ],
    },
  })
}, 60_000)

describe('session endpoint', () => {
  it('returns 401 without a session', async () => {
    expect((await call('GET', '/auth-link/session')).status).toBe(401)
  })

  it('emits no-store on session responses', async () => {
    const denied = await call('GET', '/auth-link/session')
    expect(denied.headers.get('Cache-Control')).toBe('no-store')
    const cookie = stub.issue({
      sessionId: 'sess-nostore',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const allowed = await call('GET', '/auth-link/session', { cookie })
    expect(allowed.status).toBe(200)
    expect(allowed.headers.get('Cache-Control')).toBe('no-store')
    const signedOut = await call('DELETE', '/auth-link/session', { cookie, csrf: true })
    expect(signedOut.status).toBe(200)
    expect(signedOut.headers.get('Cache-Control')).toBe('no-store')
  })

  it('returns the user for a linked provider session', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-1',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await call('GET', '/auth-link/session', { cookie })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { email: string; roles: string[] } }
    expect(body.user.email).toBe('linked@test.dev')
    expect(body.user.roles).toEqual(['admin'])
  })

  it('returns 401 for an expired provider session', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-expired',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() - 1000),
    })
    expect((await call('GET', '/auth-link/session', { cookie })).status).toBe(401)
  })

  it('provisions a user just-in-time for an unknown verified identity', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-jit',
      providerUserId: 'stub-jit',
      email: 'jit@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await call('GET', '/auth-link/session', { cookie })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { email: string; roles: string[] } }
    expect(body.user.email).toBe('jit@test.dev')
    expect(body.user.roles).toEqual(['user'])
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'jit@test.dev' } },
      limit: 1,
    })
    expect(stored.totalDocs).toBe(1)
  })

  it('returns 401 when an unverified identity would provision a new user', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-jit-unverified',
      providerUserId: 'stub-jit-unverified',
      email: 'jit-unverified@test.dev',
      emailVerified: false,
      expiresAt: new Date(Date.now() + 3600_000),
    })
    expect((await call('GET', '/auth-link/session', { cookie })).status).toBe(401)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'jit-unverified@test.dev' } },
      limit: 1,
    })
    expect(stored.totalDocs).toBe(0)
  })

  it('returns 401 when an unverified identity matches an existing user', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-takeover',
      providerUserId: 'stub-stranger',
      email: 'linked@test.dev',
      emailVerified: false,
      expiresAt: new Date(Date.now() + 3600_000),
    })
    expect((await call('GET', '/auth-link/session', { cookie })).status).toBe(401)
  })

  it('syncs the email when the provider reports a new verified address', async () => {
    await payload.create({
      collection: 'users',
      data: {
        email: 'sync@test.dev',
        password: 'correct-horse-battery',
        roles: ['admin'],
        identities: [
          {
            providerId: 'stub',
            providerUserId: 'stub-sync',
            email: 'sync@test.dev',
            linkedAt: new Date().toISOString(),
          },
        ],
      },
    })
    const cookie = stub.issue({
      sessionId: 'sess-sync',
      providerUserId: 'stub-sync',
      email: 'synced@test.dev',
      emailVerified: true,
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await call('GET', '/auth-link/session', { cookie })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { email: string } }
    expect(body.user.email).toBe('synced@test.dev')
  })
})

describe('strategy via native endpoints', () => {
  it('authenticates /api/users/me from the provider cookie', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-me',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await call('GET', '/users/me', { cookie })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { email: string } }
    expect(body.user.email).toBe('linked@test.dev')
  })
})

describe('logout endpoint', () => {
  it('requires CSRF proof', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-csrf',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    expect((await call('DELETE', '/auth-link/session', { cookie })).status).toBe(403)
    expect(
      (await call('DELETE', '/auth-link/session', { cookie, origin: 'https://evil.test' })).status
    ).toBe(403)
  })

  it('revokes the session with CSRF proof', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-revoke',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const deleted = await call('DELETE', '/auth-link/session', { cookie, csrf: true })
    expect(deleted.status).toBe(200)
    expect((await call('GET', '/auth-link/session', { cookie })).status).toBe(401)
  })

  it('accepts a matching Origin instead of the header', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-origin',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const deleted = await call('DELETE', '/auth-link/session', { cookie, origin: ORIGIN })
    expect(deleted.status).toBe(200)
  })

  it('expires provider cookies on logout', async () => {
    const cookie = stub.issue({
      sessionId: 'sess-expire',
      providerUserId: 'stub-linked',
      email: 'linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const deleted = await call('DELETE', '/auth-link/session', { cookie, csrf: true })
    expect(deleted.status).toBe(200)
    expect(deleted.headers.getSetCookie()).toEqual([`${stubCookieName}=; Max-Age=0; Path=/`])
  })

  it('expires provider cookies even when already signed out', async () => {
    const deleted = await call('DELETE', '/auth-link/session', {
      cookie: `${stubCookieName}=stale-token`,
      csrf: true,
    })
    expect(deleted.status).toBe(401)
    expect(deleted.headers.getSetCookie()).toEqual([`${stubCookieName}=; Max-Age=0; Path=/`])
  })
})

describe('failed logout', () => {
  const failingStub = createStubProvider()
  const failingProvider: IdentityProviderPort = {
    ...failingStub.provider,
    revokeSession: () =>
      errAsync(new ProviderError(failingStub.provider.id, 'revoke failed: provider down')),
  }

  it('returns 500 but still expires the session cookies', async () => {
    // Direct handler invocation against the shared Payload instance: a
    // second Payload in one file does not isolate (instance cache), so
    // the failing provider is wired here and the handler is called with
    // a real repository. Routing/CSRF are covered by the tests above.
    const wiredFailing = wireOptions({
      baseUrl: ORIGIN,
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [failingProvider],
    })
    const handlers = createEndpoints(wiredFailing)
    const logout = handlers.find((endpoint) => endpoint.method === 'delete')
    expect(logout).toBeDefined()
    if (logout === undefined) {
      throw new Error('unreachable')
    }
    const cookie = failingStub.issue({
      sessionId: 'sess-revoke-fails',
      providerUserId: 'stub-doomed',
      email: 'doomed@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await logout.handler({
      payload,
      headers: new Headers({ cookie, 'x-auth-link-csrf': '1' }),
    } as unknown as PayloadRequest)
    expect(response.status).toBe(500)
    expect(response.headers.getSetCookie()).toEqual([`${stubCookieName}=; Max-Age=0; Path=/`])
  })
})

describe('email hook', () => {
  it('stores emails lowercased', async () => {
    const created = await payload.create({
      collection: 'users',
      data: { email: 'MixedCase@test.dev', password: 'correct-horse-battery' },
    })
    expect(created.email).toBe('mixedcase@test.dev')
  })
})

describe('payload user repository', () => {
  it('round-trips users through the Local API', async () => {
    const wired = wireOptions({
      baseUrl: ORIGIN,
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [stub.provider],
    })
    const users = createPayloadUserRepository({
      payload,
      map: wired.config.map,
      defaultRole: wired.config.defaultRole,
      logger: wired.logger,
      clock: wired.clock,
      ids: wired.ids,
      depth: wired.depth,
    })
    expect((await users.findByEmail(email('repo@test.dev'))).unwrapOr(null)).toBeNull()

    const created = await users.create({ email: email('repo@test.dev'), roles: [role('user')] })
    expect(created.isOk()).toBe(true)
    if (created.isErr()) {
      throw created.error
    }
    expect(created.value.roles).toEqual(['user'])

    const duplicate = await users.create({ email: email('repo@test.dev'), roles: [role('user')] })
    expect(duplicate.isErr()).toBe(true)

    const linked = await users.linkIdentity(created.value.id, {
      providerId: defineProviderId('stub'),
      providerUserId: 'stub-repo',
    })
    expect(linked.isOk()).toBe(true)

    const found = await users.findByProviderIdentity({
      providerId: defineProviderId('stub'),
      providerUserId: 'stub-repo',
    })
    expect(found.isOk()).toBe(true)
    if (found.isOk()) {
      expect(found.value?.email).toBe('repo@test.dev')
    }

    const promoted = await users.setRoles(created.value.id, [role('admin')])
    expect(promoted.isOk()).toBe(true)
    if (promoted.isOk()) {
      expect(promoted.value.roles).toEqual(['admin'])
    }
    expect(stubCookieName).toBe('al_stub_session')
  })
})
