/**
 * Companion to integration-users-default-access.test.ts (one Payload
 * instance per file). Users-collection write defaults: Payload's own default lets ANY
 * signed-in user update or delete ANY user, and JIT sign-up makes
 * anyone on the internet "signed in". Re-pointing a local admin's
 * email and then running forgot-password for the new address was a
 * full takeover. The plugin therefore fills unset `update` (self or a
 * role manager) and `delete` (role managers), and the injected email
 * field only ever lets a non-manager change their OWN address — even
 * when the host declares a broader collection-level `update`.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type CollectionConfig,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://users-default-access.test'

type Harness = {
  readonly config: SanitizedConfig
  readonly payload: Payload
  readonly stub: ReturnType<typeof createStubProvider>
}

async function harness(users: CollectionConfig): Promise<Harness> {
  const stub = createStubProvider()
  const config = await buildConfig({
    secret: 'users-default-access-secret!!',
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [users],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
      }),
    ],
  })
  return { config, payload: await getPayload({ config }), stub }
}

function cookieFor(h: Harness, email: string): string {
  return h.stub.issue({
    sessionId: `sess-${email}-${Math.random()}`,
    providerUserId: `stub-${email}`,
    email,
    expiresAt: new Date(Date.now() + 3600_000),
  })
}

async function call(
  h: Harness,
  method: string,
  path: string,
  opts: { cookie?: string; body?: unknown } = {}
): Promise<number> {
  const headers: Record<string, string> = { origin: ORIGIN }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  const response = await handleEndpoints({
    config: h.config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  return response.status
}

/** Sign a provider user in (JIT-provisioned) and return their cookie and id. */
async function signedIn(h: Harness, email: string): Promise<{ cookie: string; id: string }> {
  const cookie = cookieFor(h, email)
  expect(await call(h, 'GET', '/auth-link/session', { cookie })).toBe(200)
  const found = await h.payload.find({
    collection: 'users',
    where: { email: { equals: email } },
    overrideAccess: true,
  })
  return { cookie, id: String(found.docs[0]?.id) }
}

async function emailOf(h: Harness, id: string): Promise<string | null> {
  const found = await h.payload.find({
    collection: 'users',
    where: { id: { equals: Number(id) } },
    overrideAccess: true,
  })
  const doc = found.docs[0] as { email?: string } | undefined
  return doc?.email ?? null
}

describe('host-declared broad update access', () => {
  it("still never lets a non-manager change another user's email", async () => {
    const h = await harness({
      slug: 'users',
      auth: true,
      access: { update: () => true },
      fields: [],
    })
    const root = await h.payload.create({
      collection: 'users',
      data: { email: 'root2@users.test', password: 'Sup3r-secret-pw', roles: ['admin'] },
      overrideAccess: true,
    })
    const member = await signedIn(h, 'member3@users.test')
    await call(h, 'PATCH', `/users/${String(root.id)}`, {
      cookie: member.cookie,
      body: { email: 'attacker2@evil.test' },
    })
    expect(await emailOf(h, String(root.id))).toBe('root2@users.test')
  }, 60_000)
})
