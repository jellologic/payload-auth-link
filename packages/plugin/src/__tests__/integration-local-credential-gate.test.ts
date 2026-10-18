/**
 * GHSA-mjvh-7vmj-pg2p: account controls on Payload's OWN credentials
 * are enforced where `req.user` is established, not per collection.
 *
 * Before the fix, suspension and the provider-owned local-credential
 * default (GHSA-f4hj, GHSA-x45w) were enforced only by the users
 * collection's operation gate and access belt (plus the per-operation
 * gate on host collections and globals), so a dead credential still
 * authenticated every surface that runs no collection operation: an
 * upload's file route, a host custom endpoint, `payload.auth()`,
 * `payload-preferences`, and `/access` grants on other collections.
 *
 * Every credential type × every surface, each proven live first (so
 * the refusal is the control, not a broken fixture). Real engine:
 * Payload on SQLite in memory, driven through `handleEndpoints`.
 */
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://local-credential-gate.test'
const SECRET = 'local-credential-gate-secret-32-chars'
const PASSWORD = 'local-credential-password-1'
const FILE_NAME = 'gated.txt'
const FUTURE = '2031-01-01T00:00:00.000Z'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

type Credential = { readonly authorization?: string; readonly cookie?: string }

function headersFor(credential: Credential): Headers {
  const headers = new Headers({ origin: ORIGIN })
  if (credential.authorization !== undefined) {
    headers.set('authorization', credential.authorization)
  }
  if (credential.cookie !== undefined) {
    headers.set('cookie', credential.cookie)
  }
  return headers
}

async function call(
  method: string,
  path: string,
  credential: Credential,
  body?: unknown
): Promise<Response> {
  const headers = headersFor(credential)
  if (body !== undefined) {
    headers.set('content-type', 'application/json')
  }
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
  })
}

type Surfaces = {
  readonly file: number
  readonly endpointUser: string | null
  readonly authUser: string | null
  readonly preferences: number
  readonly notes: { readonly create: boolean; readonly read: boolean }
}

/** A `/access` grant (Payload omits denied keys for anonymous requests). */
function grant(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value
  }
  return (
    typeof value === 'object' &&
    value !== null &&
    'permission' in value &&
    value.permission === true
  )
}

/** What the credential reaches on every surface outside the users collection. */
async function surfaces(credential: Credential): Promise<Surfaces> {
  const file = await call('GET', `/media/file/${FILE_NAME}`, credential)
  const endpoint = (await (await call('GET', '/whoami', credential)).json()) as {
    userId: string | null
  }
  const authed = await payload.auth({ headers: headersFor(credential) })
  const preferences = await call('GET', '/payload-preferences', credential)
  const access = (await (await call('GET', '/access', credential)).json()) as {
    collections?: { notes?: { create?: unknown; read?: unknown } }
  }
  const notes = access.collections?.notes ?? {}
  return {
    file: file.status,
    endpointUser: endpoint.userId,
    authUser: authed.user === null ? null : String(authed.user.id),
    preferences: preferences.status,
    notes: { create: grant(notes.create), read: grant(notes.read) },
  }
}

function live(id: string): Surfaces {
  return {
    file: 200,
    endpointUser: id,
    authUser: id,
    preferences: 200,
    notes: { create: true, read: true },
  }
}

const dead: Surfaces = {
  file: 403,
  endpointUser: null,
  authUser: null,
  preferences: 403,
  notes: { create: false, read: false },
}

async function createUser(email: string, data: Record<string, unknown>): Promise<string> {
  const created = await payload.create({
    collection: 'users',
    data: {
      email,
      password: PASSWORD,
      roles: ['user'],
      linkable: true,
      linkableEmail: email,
      ...data,
    },
    overrideAccess: true,
  })
  return String(created.id)
}

async function linkByProvider(email: string, providerUserId: string): Promise<void> {
  const linked = await call('GET', '/auth-link/session', {
    cookie: stub.issue({
      sessionId: `sess-${providerUserId}`,
      providerUserId,
      email,
      expiresAt: new Date(Date.now() + 3600_000),
    }),
  })
  expect(linked.status).toBe(200)
}

async function suspend(id: string): Promise<void> {
  await payload.update({
    collection: 'users',
    id,
    data: { suspendedUntil: FUTURE },
    overrideAccess: true,
  })
}

async function localJwt(email: string): Promise<string> {
  const login = await call('POST', '/users/login', {}, { email, password: PASSWORD })
  expect(login.status).toBe(200)
  const { token } = (await login.json()) as { token?: unknown }
  if (typeof token !== 'string') {
    throw new Error('login returned no token')
  }
  return token
}

beforeAll(async () => {
  const staticDir = mkdtempSync(join(tmpdir(), 'auth-link-gate-'))
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      // Stateless JWTs (`useSessions: false`) plus Payload API keys:
      // every Payload-issued credential type the advisory names.
      { slug: 'users', auth: { useAPIKey: true, useSessions: false }, fields: [] },
      {
        slug: 'notes',
        access: { create: ({ req }) => Boolean(req.user), read: ({ req }) => Boolean(req.user) },
        fields: [{ name: 'title', type: 'text' }],
      },
      {
        slug: 'media',
        upload: { staticDir },
        access: { read: ({ req }) => Boolean(req.user) },
        fields: [],
      },
    ],
    endpoints: [
      {
        path: '/whoami',
        method: 'get',
        handler: (req) => Response.json({ userId: req.user ? String(req.user.id) : null }),
      },
      {
        // A host endpoint reading a users document with the request's
        // `req` (the same shape as the built-in strategies' lookup).
        path: '/reads/:id',
        method: 'get',
        handler: async (req) => {
          const doc = await req.payload.findByID({
            collection: 'users',
            id: String(req.routeParams?.id),
            overrideAccess: true,
            req,
          })
          const email: unknown = doc.email
          return Response.json({ email, userId: req.user ? String(req.user.id) : null })
        },
      },
    ],
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
    collection: 'media',
    data: {},
    file: {
      data: Buffer.from('access-controlled'),
      mimetype: 'text/plain',
      name: FILE_NAME,
      size: 17,
    },
    overrideAccess: true,
  })
}, 60_000)

describe('the fixture', () => {
  it('serves nothing to an anonymous request', async () => {
    expect(await surfaces({})).toEqual(dead)
  })
})

describe("a suspended user's API key", () => {
  it('authenticates nothing once the user is suspended', async () => {
    const apiKey = 'suspended-user-api-key-0123456789'
    const id = await createUser('suspended-key@gate.test', { enableAPIKey: true, apiKey })
    const credential = { authorization: `users API-Key ${apiKey}` }
    expect(await surfaces(credential)).toEqual(live(id))
    await suspend(id)
    expect(await surfaces(credential)).toEqual(dead)
  })
})

describe('an API key re-enabled on a provider-linked document', () => {
  it('authenticates nothing', async () => {
    const email = 'linked-key@gate.test'
    const apiKey = 'pre-link-api-key-0123456789abcdef'
    const id = await createUser(email, { enableAPIKey: true, apiKey })
    expect(await surfaces({ authorization: `users API-Key ${apiKey}` })).toEqual(live(id))
    await linkByProvider(email, 'stub-linked-key')
    const reEnabled = 're-enabled-api-key-0123456789abcdef'
    await payload.update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: reEnabled },
      overrideAccess: true,
    })
    expect(await surfaces({ authorization: `users API-Key ${reEnabled}` })).toEqual(dead)
  })
})

describe('a pre-link local JWT on a host without useSessions', () => {
  it('authenticates nothing once the document is provider-linked (cookie and header)', async () => {
    const email = 'linked-jwt@gate.test'
    const id = await createUser(email, {})
    const token = await localJwt(email)
    const cookie = { cookie: `payload-token=${token}` }
    const header = { authorization: `JWT ${token}` }
    expect(await surfaces(cookie)).toEqual(live(id))
    expect(await surfaces(header)).toEqual(live(id))
    await linkByProvider(email, 'stub-linked-jwt')
    expect(await surfaces(cookie)).toEqual(dead)
    expect(await surfaces(header)).toEqual(dead)
  })
})

describe("a suspended user's local JWT", () => {
  it('authenticates nothing once the user is suspended', async () => {
    const email = 'suspended-jwt@gate.test'
    const id = await createUser(email, {})
    const credential = { authorization: `JWT ${await localJwt(email)}` }
    expect(await surfaces(credential)).toEqual(live(id))
    await suspend(id)
    expect(await surfaces(credential)).toEqual(dead)
  })
})

describe('the gate is scoped to the dead credential', () => {
  it('a live unlinked API key and a live local JWT keep working beside dead ones', async () => {
    const apiKey = 'live-unlinked-api-key-0123456789'
    const keyed = await createUser('live-key@gate.test', { enableAPIKey: true, apiKey })
    expect(await surfaces({ authorization: `users API-Key ${apiKey}` })).toEqual(live(keyed))
    const email = 'live-jwt@gate.test'
    const id = await createUser(email, {})
    expect(await surfaces({ authorization: `JWT ${await localJwt(email)}` })).toEqual(live(id))
  })

  it('a dead credential does not poison other reads of the same document', async () => {
    const email = 'reread@gate.test'
    const id = await createUser(email, {})
    const token = await localJwt(email)
    await suspend(id)
    // The request is anonymous, yet its own Local-API read of the very
    // document the credential names succeeds: the gate was consumed by
    // the strategy's lookup and touches no other read.
    const response = await call('GET', `/reads/${id}`, { authorization: `JWT ${token}` })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ email, userId: null })
  })
})
