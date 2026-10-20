/**
 * Adopt mode + Better Auth's `admin()` plugin over an adopted hasMany
 * select role — the payload-auth layout (issue #143). The adapter
 * bridges the ARRAY the column stores to the comma-joined STRING
 * Better Auth's admin plugin operates on (`admin/has-permission` runs
 * `.split(",")` on it) and splits Better Auth's joined string back into
 * the array on write. Before the bridge, `session.user.role` reached
 * `has-permission` as an array and EVERY `/api/auth/admin/*` endpoint
 * answered 500 with "TypeError: .split is not a function" — admins
 * included; `get-session` also reported `user.role` as an array where
 * Better Auth's clients expect the joined string.
 *
 * payload-auth papered over this with before/after middleware on
 * `/admin/*` (join on the way in, split on the way out); nothing
 * replaced it in payload-auth-link, so the bridge lives in the adapter
 * where every read and write already flows.
 */
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { admin } from 'better-auth/plugins'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://adopt-admin.test'
const SECRET = 'adopt-admin-role-bridge-secret'
/**
 * When set (CI's migration-fixture job, or a local Postgres), the
 * suite runs on Postgres — transaction isolation is where SQLite
 * in-memory hides nested-write bugs (issue #135). Unset: SQLite.
 */
const ADOPT_PG_URL = process.env.ADOPT_PG_URL
/** Run-scoped email suffix: the Postgres database persists across runs. */
const RUN = String(Date.now())
const PASSWORD = 'correct-horse'

const ADMIN_EMAIL = `root-${RUN}@example.com`
const MEMBER_EMAIL = `member-${RUN}@example.com`

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
    plugins: [admin()],
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

async function signUp(email: string): Promise<string> {
  const response = await engine.auth.handler(
    authRequest('/sign-up/email', {
      method: 'POST',
      body: { name: 'Adopt Admin', email, password: PASSWORD },
    })
  )
  expect(response.status, `sign-up ${email}: ${await response.clone().text()}`).toBe(200)
  const body = (await response.json()) as { user?: { id?: unknown } }
  // Adopt mode with `idStrategy: 'payload'`: the Better Auth row id IS
  // the host document id.
  if (typeof body.user?.id !== 'string') {
    throw new Error(`sign-up ${email} returned no user id`)
  }
  return body.user.id
}

async function hostDocByEmail(email: string): Promise<Record<string, unknown>> {
  const found = await payload?.find({
    collection: 'users',
    where: { email: { equals: email } },
    limit: 1,
    depth: 0,
    overrideAccess: true,
  })
  const doc = found?.docs[0]
  if (doc === undefined) {
    throw new Error(`no host user ${email}`)
  }
  return doc
}

let adminCookie = ''
let memberId = ''

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db:
      ADOPT_PG_URL === undefined
        ? sqliteAdapter({ client: { url: ':memory:' } })
        : postgresAdapter({ pool: { connectionString: ADOPT_PG_URL }, push: true }),
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
          {
            // payload-auth's shape: the role column is a hasMany select.
            name: 'role',
            type: 'select',
            hasMany: true,
            options: ['user', 'admin', 'staff'],
            defaultValue: ['user'],
          },
          { name: 'banned', type: 'checkbox', defaultValue: false },
          { name: 'banReason', type: 'text' },
          { name: 'banExpires', type: 'date' },
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
          { name: 'impersonatedBy', type: 'text' },
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
        roles: ['admin', 'staff', 'user'],
        defaultRole: 'user',
        // payload-auth's users table carried the role column: adopt
        // setups point the plugin at it (the field name below).
        rolesField: 'role',
        providers: [engine.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  await engine.auth.$context

  const adminId = await signUp(ADMIN_EMAIL)
  memberId = await signUp(MEMBER_EMAIL)

  // The grant goes through the HOST field — the operator's path after a
  // cutover (the Payload user is the only user store there is).
  await payload?.update({
    collection: 'users',
    id: adminId,
    data: { role: ['admin'] },
    overrideAccess: true,
  })
  const signIn = await engine.auth.handler(
    authRequest('/sign-in/email', {
      method: 'POST',
      body: { email: ADMIN_EMAIL, password: PASSWORD },
    })
  )
  expect(signIn.status, `admin sign-in: ${await signIn.clone().text()}`).toBe(200)
  adminCookie = sessionCookieOf(signIn)
}, 120_000)

describe(`adopt mode + admin(): the hasMany role bridges to Better Auth's joined string (issue #143; ${ADOPT_PG_URL === undefined ? 'sqlite' : 'postgres'})`, () => {
  it('get-session reports user.role as the joined string Better Auth clients expect', async () => {
    const session = await engine.auth.handler(authRequest('/get-session', { cookie: adminCookie }))
    expect(session.status).toBe(200)
    const body = (await session.json()) as { user?: { role?: unknown } | null }
    expect(body.user?.role).toBe('admin')
  })

  it('list-users answers 200 for an admin — has-permission receives a string, not an array', async () => {
    const list = await engine.auth.handler(
      authRequest('/admin/list-users?limit=1', { cookie: adminCookie })
    )
    // THE regression: before the bridge this 500s with
    // "TypeError: .split is not a function".
    expect(list.status, await list.clone().text()).toBe(200)
    const body = (await list.json()) as { users?: unknown[]; total?: number }
    expect(Array.isArray(body.users)).toBe(true)
    expect(body.total).toBeGreaterThanOrEqual(2)
  })

  it('set-role writes through to the host select as the array shape', async () => {
    const setRole = await engine.auth.handler(
      authRequest('/admin/set-role', {
        method: 'POST',
        body: { userId: memberId, role: 'admin' },
        cookie: adminCookie,
      })
    )
    expect(setRole.status, await setRole.clone().text()).toBe(200)
    // Better Auth's clients read the joined string back...
    const body = (await setRole.json()) as { user?: { role?: unknown } }
    expect(body.user?.role).toBe('admin')
    // ...while the host column keeps the array the select stores.
    expect((await hostDocByEmail(MEMBER_EMAIL))?.['role']).toEqual(['admin'])
  })

  it('a multi-role write splits into the stored array', async () => {
    const setRole = await engine.auth.handler(
      authRequest('/admin/set-role', {
        method: 'POST',
        body: { userId: memberId, role: 'user,staff' },
        cookie: adminCookie,
      })
    )
    expect(setRole.status, await setRole.clone().text()).toBe(200)
    expect((await hostDocByEmail(MEMBER_EMAIL))?.['role']).toEqual(['user', 'staff'])
  })

  it('ban-user succeeds, marks the host row, and revokes the target sessions', async () => {
    const memberSignIn = await engine.auth.handler(
      authRequest('/sign-in/email', {
        method: 'POST',
        body: { email: MEMBER_EMAIL, password: PASSWORD },
      })
    )
    expect(memberSignIn.status).toBe(200)
    const memberCookie = sessionCookieOf(memberSignIn)

    const ban = await engine.auth.handler(
      authRequest('/admin/ban-user', {
        method: 'POST',
        body: { userId: memberId },
        cookie: adminCookie,
      })
    )
    expect(ban.status, await ban.clone().text()).toBe(200)
    const doc = await hostDocByEmail(MEMBER_EMAIL)
    expect(doc?.['banned']).toBe(true)

    // GHSA-62xf's companion path: a ban is only worth anything if it
    // revokes sessions — Better Auth's deleteUserSessions must have
    // emptied the adopted session collection for the target...
    const remaining = await payload?.count({
      collection: 'userSessions',
      where: { user: { equals: memberId } },
      overrideAccess: true,
    })
    expect(remaining?.totalDocs).toBe(0)
    // ...so the cookie the target held no longer authenticates.
    const revoked = await engine.auth.handler(authRequest('/get-session', { cookie: memberCookie }))
    if (revoked.status === 200) {
      expect(await revoked.json()).toBeNull()
    } else {
      expect([401, 403]).toContain(revoked.status)
    }
  })
})
