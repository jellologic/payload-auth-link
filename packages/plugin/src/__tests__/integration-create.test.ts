/**
 * Integration tests for the create path: no users collection in the host
 * config, so the plugin creates an SSO-style one (no local password).
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

const ORIGIN = 'http://auth-link.test'
const SECRET = 'integration-secret-32-chars-min!!'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [],
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

describe('created users collection', () => {
  it('creates users without a password and applies the default role', async () => {
    const created = await payload.create({
      overrideAccess: true,
      collection: 'users',
      data: { email: 'sso@test.dev' },
    })
    expect(created.email).toBe('sso@test.dev')
    const found = await payload.findByID({
      overrideAccess: true,
      collection: 'users',
      id: created.id,
    })
    expect(found.roles).toEqual(['user'])
  })

  it('authenticates sessions end to end', async () => {
    await payload.create({
      overrideAccess: true,
      collection: 'users',
      data: {
        email: 'created@test.dev',
        roles: ['admin'],
        identities: [
          {
            providerId: 'stub',
            providerUserId: 'stub-created',
            email: 'created@test.dev',
            linkedAt: new Date().toISOString(),
          },
        ],
      },
    })
    const cookie = stub.issue({
      sessionId: 'sess-created',
      providerUserId: 'stub-created',
      email: 'created@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const response = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        headers: { cookie },
      }),
    })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { user: { roles: string[] } }
    expect(body.user.roles).toEqual(['admin'])
  })
})
