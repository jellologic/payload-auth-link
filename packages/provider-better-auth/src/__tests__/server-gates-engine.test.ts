/**
 * Server session API gates on a REAL Better Auth engine
 * (docs/security-model.md rows 1, 18, 19, 20 — previously pinned only
 * by stub providers): suspension refuses both the live session and a
 * fresh mint, revoke-all is scoped to one user, a revoke of an unknown
 * handle fails loudly, and verifyApiKey without the api-key plugin is
 * refused by capability rather than reporting "unknown key".
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink, authLinkServer, UserSuspendedError } from '@payload-auth-link/plugin'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'server-gates-engine-secret-32ch!'
const PASSWORD = 'correct-horse-battery'

let config: SanitizedConfig
let payload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!payload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(payload)
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: { enabled: false },
  },
})

function live(): Payload {
  if (!payload) {
    throw new Error('Payload not ready')
  }
  return payload
}

function authRequest(path: string, body: unknown): Request {
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

/** Sign up + verify + sign in; returns the session cookie pair. */
async function signedIn(email: string): Promise<string> {
  const signUp = await engine.auth.handler(
    authRequest('/sign-up/email', { name: 'Gate', email, password: PASSWORD })
  )
  expect(signUp.status).toBe(200)
  await live().update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: true },
    overrideAccess: true,
  })
  const signIn = await engine.auth.handler(
    authRequest('/sign-in/email', { email, password: PASSWORD })
  )
  expect(signIn.status).toBe(200)
  const name = engine.sessionCookieNames[0] ?? ''
  const entry = signIn.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  if (entry === undefined) {
    throw new Error('sign-in set no session cookie')
  }
  return entry.split(';')[0] ?? ''
}

async function pluginSession(cookie: string): Promise<Response> {
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
  })
}

async function hostIdOf(cookie: string): Promise<string> {
  const response = await pluginSession(cookie)
  expect(response.status).toBe(200)
  const body = (await response.json()) as { user?: { id?: unknown } }
  const id = body.user?.id
  if (typeof id !== 'string' && typeof id !== 'number') {
    throw new Error('the bridge resolved no user')
  }
  return String(id)
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        allowServerSessions: true,
        providers: [engine.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  await engine.auth.$context
}, 120_000)

describe('server session gates on a real Better Auth engine', () => {
  it('rows 1 + 18: suspension refuses the live session AND a server mint', async () => {
    const cookie = await signedIn('gate-suspend@test.dev')
    const hostId = await hostIdOf(cookie)
    await live().update({
      collection: 'users',
      id: hostId,
      data: { suspendedUntil: '2031-01-01T00:00:00.000Z' },
      overrideAccess: true,
    })
    expect((await pluginSession(cookie)).status).toBe(401)
    await expect(
      authLinkServer(live()).createSessionFor(hostId, { reason: 'gate-test' })
    ).rejects.toBeInstanceOf(UserSuspendedError)
  })

  it("row 19: revokeAllForUser kills one user's sessions and no one else's", async () => {
    const victim = await signedIn('gate-victim@test.dev')
    const bystander = await signedIn('gate-bystander@test.dev')
    const victimId = await hostIdOf(victim)
    await hostIdOf(bystander)
    await authLinkServer(live()).revokeAllForUser(victimId)
    expect((await pluginSession(victim)).status).toBe(401)
    expect((await pluginSession(bystander)).status).toBe(200)
  })

  it('row 19: revoking an unknown handle fails loudly', async () => {
    await expect(authLinkServer(live()).revokeSession('no-such-session-id')).rejects.toThrow(
      /^revokeSession: /
    )
  })

  it('row 20: verifyApiKey without the api-key plugin is refused by capability', async () => {
    expect(engine.provider.capabilities.has('api-key-verify')).toBe(false)
    await expect(authLinkServer(live()).verifyApiKey('pal_anything')).rejects.toThrow(
      /capability api-key-verify/
    )
  })
})
