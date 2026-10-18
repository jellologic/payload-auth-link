/**
 * Adopt mode with Payload's LOCAL strategy still on (issue #113): the
 * adopted users collection is a Payload auth collection whose local
 * registration demands a password, so every Better Auth create of a
 * user must carry the adapter's injected (unknowable) password.
 *
 * Regression: the injection used to be decided once, on the adapter's
 * first call, and only for the models planned by then. When that first
 * call was other traffic (a verification / session read), the users
 * model never got the password and every later sign-up failed with
 * Payload's 422 "The following field is invalid: password".
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://adopt-local.test'
const SECRET = 'adopt-local-strategy-secret-32-chars!'

let payload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!payload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(payload)
  },
  schemaMap: {
    user: { slug: 'users' },
    session: { slug: 'userSessions', fields: { userId: 'user' } },
    account: { slug: 'userAccounts', fields: { userId: 'user' } },
    verification: { slug: 'verifications' },
  },
  idStrategy: 'payload',
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})

function signUp(email: string): Promise<Response> {
  return engine.auth.handler(
    new Request(`${ORIGIN}/api/auth/sign-up/email`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Local', email, password: 'correct-horse-battery' }),
    })
  )
}

beforeAll(async () => {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      {
        slug: 'users',
        // Payload's local strategy stays ON: creates need a password.
        auth: true,
        fields: [
          { name: 'emailVerified', type: 'checkbox', defaultValue: false },
          { name: 'name', type: 'text' },
          { name: 'image', type: 'text' },
        ],
      },
      {
        slug: 'userSessions',
        fields: [
          { name: 'user', type: 'relationship', relationTo: 'users', required: true },
          { name: 'token', type: 'text', required: true, unique: true },
          { name: 'expiresAt', type: 'date', required: true },
          { name: 'ipAddress', type: 'text' },
          { name: 'userAgent', type: 'text' },
        ],
      },
      {
        slug: 'userAccounts',
        fields: [
          { name: 'user', type: 'relationship', relationTo: 'users', required: true },
          { name: 'accountId', type: 'text', required: true },
          { name: 'providerId', type: 'text', required: true },
          { name: 'password', type: 'text' },
          { name: 'accessToken', type: 'text' },
          { name: 'refreshToken', type: 'text' },
          { name: 'idToken', type: 'text' },
          { name: 'accessTokenExpiresAt', type: 'date' },
          { name: 'refreshTokenExpiresAt', type: 'date' },
          { name: 'scope', type: 'text' },
        ],
      },
      {
        slug: 'verifications',
        fields: [
          { name: 'identifier', type: 'text', required: true },
          { name: 'value', type: 'text', required: true },
          { name: 'expiresAt', type: 'date', required: true },
        ],
      },
    ],
  })
  payload = await getPayload({ config })
  await engine.auth.$context
}, 120_000)

describe('adopt mode with the local strategy on (issue #113)', () => {
  it('a sign-up after other adapter traffic still gets the injected password', async () => {
    const ctx = await engine.auth.$context
    // The adapter's FIRST calls touch other models only.
    expect(
      await ctx.adapter.findOne({
        model: 'verification',
        where: [{ field: 'identifier', value: 'nobody' }],
      })
    ).toBeNull()
    expect(
      await ctx.adapter.findOne({ model: 'session', where: [{ field: 'token', value: 'none' }] })
    ).toBeNull()

    const first = await signUp('first@adopt-local.test')
    expect(first.status, await first.clone().text()).toBe(200)
    const second = await signUp('second@adopt-local.test')
    expect(second.status, await second.clone().text()).toBe(200)

    const users = await payload?.find({
      collection: 'users',
      where: { email: { in: ['first@adopt-local.test', 'second@adopt-local.test'] } },
      overrideAccess: true,
    })
    expect(users?.docs).toHaveLength(2)
  })
})
