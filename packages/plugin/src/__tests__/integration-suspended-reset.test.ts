/**
 * Row 7 (docs/security-model.md): `reset-password` for a SUSPENDED
 * account must be refused BEFORE anything is written. Payload's reset
 * operation writes the new password (and clears the account's
 * sessions) before it runs `beforeLogin`; where that write is not
 * rolled back, the 401 from `beforeLogin` came too late — the
 * "refused" reset had rotated the password, which then worked the
 * moment the suspension lapsed. The guard now refuses suspended
 * documents in `beforeOperation`, before the write (issue #86). The
 * opt-out variant is pinned at unit level (collections-fail-closed).
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
const SECRET = 'suspended-reset-secret-32-chars!'
const FUTURE = '2031-01-01T00:00:00.000Z'

let config: SanitizedConfig
let payload: Payload

async function post(path: string, body: unknown): Promise<number> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify(body),
    }),
  })
  return response.status
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
        providers: [createStubProvider().provider],
      }),
    ],
  })
  payload = await getPayload({ config })
}, 60_000)

describe('reset-password on a suspended account writes nothing (row 7)', () => {
  it('refuses with 401 and the password does NOT rotate', async () => {
    const doc = await payload.create({
      collection: 'users',
      data: { email: 'susp-reset@test.dev', password: 'OriginalKnown-1', roles: ['user'] },
      overrideAccess: true,
    })
    await payload.update({
      collection: 'users',
      id: doc.id,
      data: {
        resetPasswordToken: 'susp-reset-token',
        resetPasswordExpiration: FUTURE,
        suspendedUntil: FUTURE,
      },
      overrideAccess: true,
    })
    expect(
      await post('/users/reset-password', { token: 'susp-reset-token', password: 'Attacker-1' })
    ).toBe(401)
    // Lift the suspension: the refused reset must not have rotated
    // the credential, and the token must still be unspent.
    await payload.update({
      collection: 'users',
      id: doc.id,
      data: { suspendedUntil: null },
      overrideAccess: true,
    })
    expect(
      await post('/users/login', { email: 'susp-reset@test.dev', password: 'Attacker-1' })
    ).toBe(401)
    expect(
      await post('/users/login', { email: 'susp-reset@test.dev', password: 'OriginalKnown-1' })
    ).toBe(200)
  })
})
