/**
 * Adopt mode, END TO END through the plugin (issue #124): a user who
 * signs up AFTER the cutover — the engine writes the host users row
 * itself, under its own user id as the document id — must resolve to a
 * Payload user on their next request, with the default role. Before
 * the fix the JIT step treated the row as a foreign email collision
 * (no ownership proof) and tried to create a second document: a valid
 * provider session with `req.user` null forever.
 *
 * Each step fails without its fix:
 * 1. sign-up → sign-in resolves through /api/auth-link/session — the
 *    id link (`findByProviderOwnedId`) attaches the engine's own row
 *    and writes the identities row `adopt-prelink` writes for
 *    pre-cutover users;
 * 2. the new user carries the default role — the create hook
 *    normalizes the hasMany select (a scalar or nothing from the
 *    engine stores nothing);
 * 3. a scalar `role` on a Local API create stores as the array shape.
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
import { anonymous } from 'better-auth/plugins'
import { createBetterAuthEngine } from '../engine.js'
import { authLink } from '@payload-auth-link/plugin'

const ORIGIN = 'http://adopt-signup.test'
const SECRET = 'adopt-signup-through-plugin-secret'

let config: SanitizedConfig
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
  autoDeclare: true,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    plugins: [anonymous()],
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})

function authRequest(
  path: string,
  init: { method?: string; body?: unknown; cookie?: string } = {}
) {
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: init.method ?? 'GET',
    headers: {
      origin: ORIGIN,
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(init.cookie === undefined ? {} : { cookie: init.cookie }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  })
}

function sessionCookieOf(response: Response): string {
  const name = engine.sessionCookieNames[0] ?? ''
  const entry = response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith(`${name}=`))
    ?.split(';')[0]
  if (entry === undefined || entry === `${name}=`) {
    throw new Error(`no session cookie set (status ${String(response.status)})`)
  }
  return entry
}

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
        slug: 'users',
        auth: {
          disableLocalStrategy: true,
          strategies: [
            { name: 'better-auth', authenticate: () => Promise.resolve({ user: null }) },
          ],
        },
        fields: [
          { name: 'email', type: 'email', required: true, index: true },
          { name: 'emailVerified', type: 'checkbox', defaultValue: false },
          { name: 'name', type: 'text' },
          { name: 'image', type: 'text' },
          { name: 'isAnonymous', type: 'checkbox', defaultValue: false },
          {
            name: 'role',
            type: 'select',
            hasMany: true,
            options: ['user', 'admin', 'staff'],
            defaultValue: ['user'],
          },
        ],
      },
      {
        slug: 'userSessions',
        fields: [
          { name: 'user', type: 'relationship', relationTo: 'users', required: true, index: true },
          { name: 'token', type: 'text', required: true, unique: true, index: true },
          { name: 'expiresAt', type: 'date', required: true },
          { name: 'ipAddress', type: 'text' },
          { name: 'userAgent', type: 'text' },
        ],
      },
      {
        slug: 'userAccounts',
        fields: [
          { name: 'user', type: 'relationship', relationTo: 'users', required: true, index: true },
          { name: 'accountId', type: 'text', required: true, index: true },
          { name: 'providerId', type: 'text', required: true, index: true },
          { name: 'password', type: 'text' },
          { name: 'accessToken', type: 'text' },
          { name: 'refreshToken', type: 'text' },
          { name: 'idToken', type: 'text' },
          { name: 'accessTokenExpiresAt', type: 'date' },
          { name: 'refreshTokenExpiresAt', type: 'date' },
        ],
      },
      {
        slug: 'verifications',
        fields: [
          { name: 'identifier', type: 'text', required: true, index: true },
          { name: 'value', type: 'text', required: true },
          { name: 'expiresAt', type: 'date', required: true },
        ],
      },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        // payload-auth's users table carried the role column: adopt
        // setups point the plugin at it (the field name below).
        rolesField: 'role',
        // Issue #126: guests resolve to their own document.
        admitAnonymous: true,
        providers: [engine.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  await engine.auth.$context
}, 120_000)

describe('adopt mode: a post-cutover sign-up resolves through the plugin (issue #124)', () => {
  it('links the engine-created row on first resolution and applies the default role', async () => {
    const signUp = await engine.auth.handler(
      authRequest('/sign-up/email', {
        method: 'POST',
        body: { name: 'Post Cutover', email: 'late@example.com', password: 'correct-horse' },
      })
    )
    expect(signUp.status).toBe(200)
    // Issue #132 part 3: the identity row is written AT CREATION — a
    // sign-up that never completes sign-in (unverified email) is still
    // linked, so `verify` never reports a permanent mismatch.
    const justCreated = await payload?.find({
      collection: 'users',
      where: { email: { equals: 'late@example.com' } },
      limit: 1,
      overrideAccess: true,
    })
    const freshDoc = justCreated?.docs[0] as Record<string, unknown> | undefined
    expect(Array.isArray(freshDoc?.identities)).toBe(true)
    expect(freshDoc?.identities).toHaveLength(1)
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'late@example.com', password: 'correct-horse' },
      })
    )
    expect(signIn.status).toBe(200)
    const cookie = sessionCookieOf(signIn)

    const session = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(session.status).toBe(200)
    const body = (await session.json()) as {
      user: { id: string; roles?: string[]; email: string } | null
    }
    expect(body.user).not.toBeNull()
    expect(body.user?.email).toBe('late@example.com')
    expect(body.user?.roles).toEqual(['user'])

    // The link wrote the identities row (the same one `adopt-prelink`
    // writes), and the row carries the default role in the host field.
    const doc = await payload?.findByID({ collection: 'users', id: body.user?.id ?? '' })
    const roles: unknown = doc?.['role']
    expect(roles).toEqual(['user'])
    const identities: unknown = doc?.['identities']
    expect(Array.isArray(identities)).toBe(true)
    expect(identities).toHaveLength(1)
  })

  it('a second request resolves from the identity row, not the id', async () => {
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'late@example.com', password: 'correct-horse' },
      })
    )
    const cookie = sessionCookieOf(signIn)
    const session = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(session.status).toBe(200)
    const body = (await session.json()) as { user: { id: string; roles?: string[] } | null }
    expect(body.user?.roles).toEqual(['user'])
    const doc = await payload?.findByID({ collection: 'users', id: body.user?.id ?? '' })
    expect(doc?.['identities']).toHaveLength(1)
  })

  it('a scalar role on a Local API create stores as the array shape', async () => {
    const created = await payload?.create({
      collection: 'users',
      data: {
        email: 'scalar-role@example.com',
        // The engine (Better Auth's additionalField) hands the plugin a
        // plain string; the field is a hasMany select.
        role: 'staff',
      },
      overrideAccess: true,
    })
    expect(created?.['role']).toEqual(['staff'])
  })

  it('an anonymous guest resolves to its own document with the marker (admitAnonymous, #126)', async () => {
    const guest = await engine.auth.handler(
      authRequest('/sign-in/anonymous', { method: 'POST', body: {} })
    )
    expect(guest.status, `guest sign-in: ${await guest.clone().text()}`).toBe(200)
    const cookie = sessionCookieOf(guest)

    const session = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(session.status).toBe(200)
    const body = (await session.json()) as {
      user: { id: string; roles?: string[]; email: string; anonymous?: boolean } | null
    }
    // The guest is a USER now — own document, roles, and the marker
    // access functions key on.
    expect(body.user).not.toBeNull()
    expect(body.user?.anonymous).toBe(true)
    expect(body.user?.roles).toEqual(['user'])
    const doc = await payload?.findByID({ collection: 'users', id: body.user?.id ?? '' })
    expect(doc?.['isAnonymous']).toBe(true)
    expect(doc?.['identities']).toHaveLength(1)
  })

  it('a named user carries no anonymous marker', async () => {
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: 'late@example.com', password: 'correct-horse' },
      })
    )
    const session = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        headers: { cookie: sessionCookieOf(signIn) },
      }),
    })
    const body = (await session.json()) as { user: { anonymous?: boolean } | null }
    expect(body.user?.anonymous).toBeUndefined()
  })
})
