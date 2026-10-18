/**
 * GHSA-j68x-qjr5-vqv9 under a renamed `suspendedUntilField`: the
 * account controls `authLinkServer(payload).verifyApiKey` applies read
 * the CONFIGURED suspension field (`bannedUntil` here), not the
 * literal `suspendedUntil`. Real engine: real Better Auth + the real
 * `@better-auth/api-key` satellite on real Payload storage (SQLite in
 * memory).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { apiKey } from '@better-auth/api-key'
import { authLink, authLinkServer } from '@payload-auth-link/plugin'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://api-key-rename.test'
const SECRET = 'api-key-rename-integration-secret!!'

let payload: Payload
let latePayload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  autoDeclare: true,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: { enabled: false },
    plugins: [apiKey([{ configId: 'default', defaultPrefix: 'pal_' }])],
  },
})

beforeAll(async () => {
  const config = await buildConfig({
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
        suspendedUntilField: 'bannedUntil',
      }),
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
}, 120_000)

describe('verifyApiKey honours a renamed suspendedUntilField (GHSA-j68x-qjr5-vqv9)', () => {
  it('refuses the key while bannedUntil is in the future, and verifies once it lapses', async () => {
    const email = 'renamed-key-owner@test.dev'
    const signUp = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-up/email`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ name: email, email, password: 'correct-horse-battery' }),
      })
    )
    expect(signUp.status).toBe(200)
    const body = (await signUp.json()) as { user?: { id?: unknown } }
    const userId = typeof body.user?.id === 'string' ? body.user.id : ''
    expect(userId).not.toBe('')
    const host = await payload.create({
      collection: 'users',
      data: {
        email,
        password: 'unused-local-password-1',
        identities: [
          {
            providerId: 'better-auth',
            providerUserId: userId,
            email,
            linkedAt: new Date().toISOString(),
          },
        ],
      },
      overrideAccess: true,
    })
    const created = (await engine.auth.api.createApiKey({ body: { userId } })) as {
      key?: unknown
    }
    const key = typeof created.key === 'string' ? created.key : ''
    expect(key.startsWith('pal_')).toBe(true)
    const server = authLinkServer(payload)
    expect((await server.verifyApiKey(key))?.userId).toBe(userId)

    const ban = async (until: string) => {
      await payload.update({
        collection: 'users',
        id: host.id,
        data: { bannedUntil: until },
        overrideAccess: true,
      })
    }
    await ban(new Date(Date.now() + 86_400_000).toISOString())
    await expect(server.verifyApiKey(key)).resolves.toBeNull()
    await ban(new Date(Date.now() - 1000).toISOString())
    expect((await server.verifyApiKey(key))?.userId).toBe(userId)
  })
})
