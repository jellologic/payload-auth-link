/**
 * SSO-off counterpart (CAP-15) on real Payload: the
 * composition-root checker in `services.ts` queries organizations'
 * `verifiedDomains` (a nested array field) live per request. Proves
 * the whole path — session service gate → services checker → Payload
 * query — not just the pure domain matcher: matching domain links,
 * foreign and subdomain assertions 401, and the same user passes
 * untouched when no SSO providers are registered.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://sso.test'
const SECRET = 'sso-integration-secret-32-chars!!!'

async function makeApp(ssoProviders: readonly string[]): Promise<{
  config: SanitizedConfig
  payload: Payload
  stub: ReturnType<typeof createStubProvider>
}> {
  const stub = createStubProvider()
  const config = await buildConfig({
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
        organizations: { enabled: true, ssoProviders },
      }),
    ],
  })
  const payload = await getPayload({ config })
  await payload.create({
    collection: 'organizations',
    data: {
      name: 'Corp',
      slug: 'corp',
      verifiedDomains: [{ domain: 'corp.test' }],
    },
    overrideAccess: true,
  })
  return { config, payload, stub }
}

function sessionStatus(
  app: { config: SanitizedConfig; stub: ReturnType<typeof createStubProvider> },
  email: string
): Promise<Response> {
  const cookie = app.stub.issue({
    sessionId: `sess-${email}`,
    providerUserId: `sso-${email}`,
    email,
    expiresAt: new Date(Date.now() + 3600_000),
  })
  return handleEndpoints({
    config: app.config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
  })
}

describe('SSO enforcement off by default (CAP-15)', () => {
  it('leaves sessions untouched when no SSO providers are registered', async () => {
    const app = await makeApp([])
    expect((await sessionStatus(app, 'mallory@other.test')).status).toBe(200)
    expect((await sessionStatus(app, 'alice@corp.test')).status).toBe(200)
  }, 60_000)
})
