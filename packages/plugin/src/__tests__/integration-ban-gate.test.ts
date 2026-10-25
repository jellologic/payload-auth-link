/**
 * GHSA-6244-vvv9-76f5: the Payload-side account gate never looked at
 * Better Auth's ban (`banned` + `banExpires`, adopted columns of the
 * users document), so a banned user kept working through every
 * credential that does not pass the provider — Payload API keys, local
 * JWTs, and principals a host strategy resolves itself (`_strategy:
 * 'mcp-api-key'`, as @payloadcms/plugin-mcp sets). The same account
 * SUSPENDED was refused everywhere; this pins ban parity on each
 * surface, each proven live first (an admin control keeps working, so
 * the refusal is the control, not a broken fixture). Real engine:
 * Payload on SQLite in memory, driven through `handleEndpoints`.
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
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://ban-gate.test'
const SECRET = 'ban-gate-secret-32-chars!!'
const PASSWORD = 'ban-gate-password-1'
const PAST = '2021-01-01T00:00:00.000Z'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

type Credential = {
  readonly authorization?: string
  readonly cookie?: string
  readonly mcp?: string
}

function headersFor(credential: Credential): Headers {
  const headers = new Headers({ origin: ORIGIN })
  if (credential.authorization !== undefined) {
    headers.set('authorization', credential.authorization)
  }
  if (credential.cookie !== undefined) {
    headers.set('cookie', credential.cookie)
  }
  if (credential.mcp !== undefined) {
    headers.set('x-mcp-principal', credential.mcp)
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

async function json(response: Response): Promise<unknown> {
  return (await response.json()) as unknown
}

/** The `users` principal a host strategy resolves itself (MCP shape). */
function mcp(id: string): Credential {
  return { mcp: id }
}

async function localJwt(email: string): Promise<Credential> {
  const login = await call('POST', '/users/login', {}, { email, password: PASSWORD })
  expect(login.status, `login ${email}: ${login.status}`).toBe(200)
  const { token } = (await json(login)) as { token?: unknown }
  if (typeof token !== 'string') {
    throw new Error('login returned no token')
  }
  return { authorization: `JWT ${token}` }
}

const API_KEY: Record<string, string> = {}

function apiKeyCredential(email: string): Credential {
  const key = API_KEY[email]
  if (key === undefined) {
    throw new Error(`no api key enabled for ${email}`)
  }
  return { authorization: `users API-Key ${key}` }
}

async function createUser(email: string, extra: Record<string, unknown>): Promise<string> {
  const key = `${email}-api-key-0123456789abcdef`
  API_KEY[email] = key
  const created = await payload.create({
    collection: 'users',
    data: {
      email,
      password: PASSWORD,
      roles: ['admin'],
      enableAPIKey: true,
      apiKey: key,
      ...extra,
    },
    overrideAccess: true,
  })
  return String(created.id)
}

async function noteId(): Promise<string> {
  const created = await payload.create({
    collection: 'notes',
    data: { title: 'gate note' },
    overrideAccess: true,
  })
  return String(created.id)
}

let liveId = ''
let bannedId = ''
let expiredId = ''
let note = ''

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      {
        // The adopt-mode shape for the columns Better Auth's admin
        // plugin writes, plus Payload's own credentials the gate must
        // veto. Versions stay on: readVersions is one of the surfaces.
        slug: 'users',
        auth: {
          useAPIKey: true,
          useSessions: false,
          strategies: [
            {
              name: 'mcp-api-key',
              authenticate: async (args) => {
                const { headers, payload: instance } = args as {
                  headers: Headers
                  payload: Payload
                }
                const id = headers.get('x-mcp-principal')
                if (id === null || id === '') {
                  return { user: null }
                }
                const doc = await instance.findByID({
                  collection: 'users',
                  id,
                  overrideAccess: true,
                })
                return {
                  user: {
                    ...doc,
                    collection: 'users',
                    _strategy: 'mcp-api-key',
                  },
                }
              },
            },
          ],
        },
        fields: [
          { name: 'banned', type: 'checkbox' },
          { name: 'banExpires', type: 'date' },
        ],
        versions: true,
      },
      {
        slug: 'notes',
        access: {
          create: ({ req }) => Boolean(req.user),
          read: ({ req }) => Boolean(req.user),
          update: ({ req }) => Boolean(req.user),
          delete: ({ req }) => Boolean(req.user),
        },
        fields: [{ name: 'title', type: 'text' }],
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
  liveId = await createUser('live@test.dev', {})
  bannedId = await createUser('banned@test.dev', { banned: true })
  expiredId = await createUser('expired@test.dev', { banned: true, banExpires: PAST })
  note = await noteId()
}, 60_000)

describe('an active ban refuses every non-provider credential (GHSA-6244)', () => {
  it('a banned admin signs in locally — refused like a suspension', async () => {
    const login = await call(
      'POST',
      '/users/login',
      {},
      {
        email: 'banned@test.dev',
        password: PASSWORD,
      }
    )
    expect(login.status).toBe(401)
    expect(JSON.stringify(await json(login))).toContain('Account banned')
  })

  it('a banned admin cannot reset a local password — nothing rotates', async () => {
    await payload.update({
      collection: 'users',
      id: bannedId,
      data: {
        resetPasswordToken: 'banned-reset-token',
        resetPasswordExpiration: '2031-01-01T00:00:00.000Z',
      },
      overrideAccess: true,
    })
    const reset = await call(
      'POST',
      '/users/reset-password',
      {},
      {
        token: 'banned-reset-token',
        password: 'RotatedAttempt-1',
      }
    )
    expect(reset.status).toBe(401)
    // The credential must NOT have rotated: the ban, not the new
    // password, decides what works when the ban lifts.
    const login = await call(
      'POST',
      '/users/login',
      {},
      {
        email: 'banned@test.dev',
        password: PASSWORD,
      }
    )
    expect(login.status).toBe(401)
  })

  it('a ban applied to a live JWT kills it on the next request', async () => {
    // The advisory's shape: the credential predates the ban. The veto
    // lives where Payload's JWT strategy reads the user, so the token
    // resolves to NOBODY the moment the ban lands.
    const mid = await createUser('mid@test.dev', {})
    const credential = await localJwt('mid@test.dev')
    const before = await call('GET', `/notes/${note}`, credential)
    expect(before.status).toBe(200)
    await payload.update({
      collection: 'users',
      id: mid,
      data: { banned: true },
      overrideAccess: true,
    })
    const me = (await json(await call('GET', '/users/me', credential))) as { user?: unknown }
    expect(me.user ?? null).toBeNull()
    const after = await call('GET', `/notes/${note}`, credential)
    expect(after.status).toBe(403)
    const versions = await call('GET', '/users/versions?limit=10', credential)
    expect(versions.status).toBe(403)
    // The users collection's own grant map (the access belt): no grant
    // survives the ban.
    const access = (await json(await call('GET', '/access', credential))) as {
      collections?: { users?: { read?: unknown } }
    }
    expect(access.collections?.users?.read).toBeFalsy()
  })

  it('a banned admin’s Payload API key authenticates nothing', async () => {
    const live = apiKeyCredential('live@test.dev')
    const liveAuth = await payload.auth({ headers: headersFor(live) })
    expect(liveAuth.user === null ? null : String(liveAuth.user.id)).toBe(liveId)
    const liveNote = await call('GET', `/notes/${note}`, live)
    expect(liveNote.status).toBe(200)

    const banned = apiKeyCredential('banned@test.dev')
    const auth = await payload.auth({ headers: headersFor(banned) })
    expect(auth.user).toBeNull()
    const read = await call('GET', `/notes/${note}`, banned)
    expect(read.status).toBe(403)
    const update = await call('PATCH', `/notes/${note}`, banned, { title: 'nope' })
    expect(update.status).toBe(403)
    const remove = await call('DELETE', `/notes/${note}`, banned)
    expect(remove.status).toBe(403)
    const versions = await call('GET', '/users/versions?limit=10', banned)
    expect(versions.status).toBe(403)
  })

  it('a banned principal a host strategy resolves (MCP shape) is refused', async () => {
    const live = mcp(liveId)
    const liveNote = await call('GET', `/notes/${note}`, live)
    expect(liveNote.status, 'control: the same principal shape works unbanned').toBe(200)

    const banned = mcp(bannedId)
    const read = await call('GET', `/notes/${note}`, banned)
    expect(read.status).toBe(401)
    const update = await call('PATCH', `/notes/${note}`, banned, { title: 'nope' })
    expect(update.status).toBe(401)
    const remove = await call('DELETE', `/notes/${note}`, banned)
    expect(remove.status).toBe(401)
    const create = await call('POST', '/notes', banned, { title: 'nope' })
    expect(create.status).toBe(401)
    const versions = await call('GET', '/users/versions?limit=10', banned)
    expect(versions.status).toBe(401)
    // The users collection's grant map refuses the banned principal;
    // host collections' maps may overstate (documented), their
    // OPERATIONS are what the gate refuses above.
    const access = (await json(await call('GET', '/access', banned))) as {
      collections?: { users?: { read?: unknown } }
    }
    expect(access.collections?.users?.read).toBeFalsy()
  })

  it('an expired ban is lifted everywhere', async () => {
    const jwt = await localJwt('expired@test.dev')
    const auth = await payload.auth({ headers: headersFor(jwt) })
    expect(auth.user === null ? null : String(auth.user.id)).toBe(expiredId)
    const note_ = await call('GET', `/notes/${note}`, jwt)
    expect(note_.status).toBe(200)
    const versions = await call('GET', '/users/versions?limit=10', jwt)
    expect(versions.status).toBe(200)
    const key = apiKeyCredential('expired@test.dev')
    const keyAuth = await payload.auth({ headers: headersFor(key) })
    expect(keyAuth.user === null ? null : String(keyAuth.user.id)).toBe(expiredId)
    const mcpPrincipal = mcp(expiredId)
    const mcpNote = await call('GET', `/notes/${note}`, mcpPrincipal)
    expect(mcpNote.status).toBe(200)
    const login = await call(
      'POST',
      '/users/login',
      {},
      {
        email: 'expired@test.dev',
        password: PASSWORD,
      }
    )
    expect(login.status).toBe(200)
  })
})
