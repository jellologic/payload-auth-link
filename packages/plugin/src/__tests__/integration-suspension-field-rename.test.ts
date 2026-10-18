/**
 * Suspension under a renamed `suspendedUntilField`: the local-sign-in
 * refusal, the reset refusal, and the request-time gates all read the
 * CONFIGURED field. They used to read `suspendedUntil` literally, so a
 * host that renamed the field (`bannedUntil` here) suspended nobody
 * outside the provider strategy. Real engine: Payload on SQLite in
 * memory, driven through `handleEndpoints`.
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

const ORIGIN = 'http://suspension-rename.test'
const SECRET = 'suspension-rename-secret-32-chars!'
const PASSWORD = 'suspension-rename-password-1'

let config: SanitizedConfig
let payload: Payload

async function call(
  method: string,
  path: string,
  opts: { authorization?: string; body?: unknown } = {}
): Promise<Response> {
  const headers: Record<string, string> = { origin: ORIGIN }
  if (opts.authorization !== undefined) {
    headers.authorization = opts.authorization
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
        providers: [createStubProvider().provider],
        suspendedUntilField: 'bannedUntil',
      }),
    ],
  })
  payload = await getPayload({ config })
}, 60_000)

describe('a renamed suspension field', () => {
  it('refuses the local JWT, local sign-in, and the user at payload.auth', async () => {
    const email = 'renamed@suspension.test'
    const created = await payload.create({
      collection: 'users',
      data: { email, password: PASSWORD, roles: ['user'] },
      overrideAccess: true,
    })
    const id = String(created.id)
    const login = await call('POST', '/users/login', { body: { email, password: PASSWORD } })
    expect(login.status).toBe(200)
    const { token } = (await login.json()) as { token: string }
    const authorization = `JWT ${token}`
    expect((await call('GET', `/users/${id}`, { authorization })).status).toBe(200)

    await payload.update({
      collection: 'users',
      id,
      data: { bannedUntil: '2031-01-01T00:00:00.000Z' },
      overrideAccess: true,
    })

    // The token resolves no user any more: the users read is anonymous.
    expect((await call('GET', `/users/${id}`, { authorization })).status).toBe(403)
    const authed = await payload.auth({ headers: new Headers({ authorization }) })
    expect(authed.user).toBeNull()
    // And a fresh local sign-in is refused.
    const again = await call('POST', '/users/login', { body: { email, password: PASSWORD } })
    expect(again.status).toBe(401)
  })
})
