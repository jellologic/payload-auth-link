/**
 * Local sessions issued before linking, on a host WITHOUT Payload's
 * server-side sessions (`auth.useSessions: false`): the JWT is
 * stateless, so clearing the sessions array cannot reach it. The
 * provider-owned local-JWT gate (collections.ts) refuses it on the
 * next operation instead. Real engine: Payload on SQLite in memory.
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

const ORIGIN = 'http://prelink-stateless.test'
const SECRET = 'prelink-stateless-secret-32-chars!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

async function rest(
  method: string,
  path: string,
  opts: { cookie?: string; body?: unknown } = {}
): Promise<Response> {
  const headers: Record<string, string> = { origin: ORIGIN, 'x-auth-link-csrf': '1' }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
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
    collections: [{ slug: 'users', auth: { useSessions: false }, fields: [] }],
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
}, 60_000)

describe('stateless local JWTs issued before linking', () => {
  it('are refused once the document is provider-owned', async () => {
    const email = 'stateless@prelink.test'
    const password = 'stateless-password-1'
    const created = await payload.create({
      collection: 'users',
      data: { email, password, roles: ['user'], linkable: true, linkableEmail: email },
      overrideAccess: true,
    })
    const login = await rest('POST', '/users/login', { body: { email, password } })
    expect(login.status).toBe(200)
    const jwt = (login.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
    expect(jwt).toMatch(/^payload-token=./)
    // Before the link the JWT works.
    expect((await rest('GET', `/users/${String(created.id)}`, { cookie: jwt })).status).toBe(200)

    const linked = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-stateless',
        providerUserId: 'stub-stateless',
        email,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(linked.status).toBe(200)

    // After it, every operation under the pre-link JWT is refused.
    const read = await rest('GET', `/users/${String(created.id)}`, { cookie: jwt })
    expect(read.status).toBe(401)
    const write = await rest('PATCH', `/users/${String(created.id)}`, {
      cookie: jwt,
      body: { email: 'moved@prelink.test' },
    })
    expect(write.status).toBe(401)
    const doc = await payload.findByID({
      collection: 'users',
      id: created.id,
      overrideAccess: true,
    })
    expect(doc.email).toBe(email)
  })
})
