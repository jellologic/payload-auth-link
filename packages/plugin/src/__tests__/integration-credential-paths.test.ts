/**
 * Credential-path matrix (docs/security-model.md): every way a session
 * or credential for the users collection can be created or used,
 * walked against the account controls — suspension (GHSA-f4hj: every
 * strategy, at request time), the MFA policy on local credentials,
 * role governance, and the provider-owned local-credential default.
 * A new credential path cannot ship without a row here.
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
const SECRET = 'credential-paths-secret-32!'
const PASSWORD = 'correct-horse-battery'
const SUSPENDED_UNTIL = '2031-01-01T00:00:00.000Z'
const TOKEN_EXPIRES = '2031-01-01T00:00:00.000Z'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider({ capabilities: ['mfa'] })

type Response = { status: number; body: unknown; headers: Headers }

async function raw(
  method: string,
  path: string,
  opts: { jar?: string; body?: unknown; authorization?: string } = {}
): Promise<Response> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    origin: ORIGIN,
  }
  if (opts.jar !== undefined) {
    headers.cookie = opts.jar
  }
  if (opts.authorization !== undefined) {
    headers.authorization = opts.authorization
  }
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body, headers: response.headers }
}

function setCookieOf(headers: Headers): string {
  return (headers.get('set-cookie') ?? '').split(';')[0] ?? ''
}

async function login(email: string, password: string): Promise<Response> {
  return raw('POST', '/users/login', { body: { email, password } })
}

/** The seeded documents' ids, resolved after creation. */
const ids: Record<string, string | number> = {}

/** A seeded document id, guaranteed present after the setup block. */
function idOf(key: string): string {
  const value = ids[key]
  if (typeof value !== 'string' && typeof value !== 'number') {
    throw new Error(`seed id missing: ${key}`)
  }
  return String(value)
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
        // The runbook shape plus a host-enabled API key channel: every
        // credential surface the audit matrix names.
        auth: { useAPIKey: true },
        fields: [],
      },
      { slug: 'pages', fields: [{ name: 'title', type: 'text', required: true }] },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user', 'auditor'],
        defaultRole: 'user',
        // `auditor` doubles as a manager role so the MFA projection is
        // observable through authorization (a manager without MFA
        // proof must lose the grant, not just the label).
        roleManagerRoles: ['admin', 'auditor'],
        policies: { requireMfaForRoles: ['auditor'] },
        providers: [stub.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  const create = async (slug: string, data: Record<string, unknown>): Promise<string | number> => {
    const doc = await payload.create({ collection: slug, data, overrideAccess: true })
    return doc.id
  }
  ids.admin = await create('users', {
    email: 'admin@test.dev',
    password: PASSWORD,
    roles: ['admin'],
  })
  // Provider-linked, currently in good standing.
  ids.linked = await create('users', {
    email: 'linked@test.dev',
    password: 'LinkedKnown-1',
    roles: ['user'],
    linkable: true,
    linkableEmail: 'linked@test.dev',
    identities: [
      {
        providerId: 'stub',
        providerUserId: 'linked-1',
        email: 'linked@test.dev',
        linkedAt: new Date().toISOString(),
      },
    ],
  })
  // Suspended WITHOUT linked identities: isolates the suspension
  // controls (the local JWT below is minted before the suspension
  // lands, proving the request-time gate).
  ids.suspended = await create('users', {
    email: 'suspended@test.dev',
    password: 'SuspendedKnown-1',
    roles: ['user'],
  })
  // Suspended AND linked: the provider-session and forgot/reset rows.
  ids.suspendedLinked = await create('users', {
    email: 'suspended-linked@test.dev',
    password: 'SuspendedLinked-1',
    roles: ['user'],
    suspendedUntil: SUSPENDED_UNTIL,
    suspendReason: 'matrix',
    linkable: true,
    linkableEmail: 'suspended-linked@test.dev',
    identities: [
      {
        providerId: 'stub',
        providerUserId: 'suspended-linked-1',
        email: 'suspended-linked@test.dev',
        linkedAt: new Date().toISOString(),
      },
    ],
  })
  // Holds the MFA-policy role through a LOCAL password: login is not
  // blocked — the projection withholds the role from the session.
  ids.mfa = await create('users', {
    email: 'mfa@test.dev',
    password: 'MfaKnown-1',
    roles: ['user', 'auditor'],
  })
  // The MFA-policy role through a provider session WITHOUT proof.
  ids.auditorLinked = await create('users', {
    email: 'auditor-linked@test.dev',
    // Host auth collections require a password on create; the
    // provider owns this document, so the credential is unusable.
    password: 'AuditorLinked-1',
    roles: ['user', 'auditor'],
    linkable: true,
    linkableEmail: 'auditor-linked@test.dev',
    identities: [
      {
        providerId: 'stub',
        providerUserId: 'auditor-linked-1',
        email: 'auditor-linked@test.dev',
        linkedAt: new Date().toISOString(),
      },
    ],
  })
  // Created outside the plugin: never JIT-linked.
  ids.unproven = await create('users', {
    email: 'unproven@test.dev',
    password: 'AttackerKnows-1',
    roles: ['user'],
    linkable: false,
  })

  // Channels minted BEFORE the suspension lands, so the walk proves
  // the request-time gate rather than the login gate.
  const suspendedLogin = await login('suspended@test.dev', 'SuspendedKnown-1')
  expect(suspendedLogin.status).toBe(200)
  ids.suspendedJwtCookie = setCookieOf(suspendedLogin.headers)
  await payload.update({
    collection: 'users',
    id: ids.suspended,
    data: { enableAPIKey: true, apiKey: 'suspended-api-key-0123456789abcdef' },
    overrideAccess: true,
  })
  await payload.update({
    collection: 'users',
    id: ids.suspended,
    data: {
      resetPasswordToken: 'suspended-reset-token',
      resetPasswordExpiration: TOKEN_EXPIRES,
    },
    overrideAccess: true,
  })
  await payload.update({
    collection: 'users',
    id: ids.linked,
    data: {
      resetPasswordToken: 'linked-reset-token',
      resetPasswordExpiration: TOKEN_EXPIRES,
    },
    overrideAccess: true,
  })
  // The suspension arrives AFTER the credentials exist.
  await payload.update({
    collection: 'users',
    id: ids.suspended,
    data: { suspendedUntil: SUSPENDED_UNTIL, suspendReason: 'matrix' },
    overrideAccess: true,
  })
}, 60_000)

/** Authorization map probe: what the request's session may do. */
async function accessOf(opts: {
  jar?: string
  authorization?: string
}): Promise<{ canAccessAdmin: unknown; usersUpdate: unknown }> {
  const access = await raw('GET', '/access', opts)
  expect(access.status).toBe(200)
  const body = access.body as {
    canAccessAdmin?: boolean
    collections: { users?: { update?: { permission?: boolean } | boolean } }
  }
  const users = body.collections.users ?? {}
  const update = typeof users.update === 'boolean' ? users.update : users.update?.permission
  return { canAccessAdmin: body.canAccessAdmin, usersUpdate: update }
}

describe('credential paths for a suspended account are refused (every channel)', () => {
  it('provider cookie: verify refused, operations refused', async () => {
    const jar = stub.issue({
      sessionId: 'sess-susp-linked',
      providerUserId: 'suspended-linked-1',
      email: 'suspended-linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const session = await raw('GET', '/auth-link/session', { jar })
    expect(session.status).toBe(401)
    // A direct operation with the provider session is equally dead:
    // verification refused the session, so the request is anonymous
    // and the default access denies the write.
    const attempt = await raw('POST', '/pages', {
      jar,
      body: { title: 'nope' },
    })
    expect([401, 403]).toContain(attempt.status)
  })

  it('existing local JWT: refused on the next request (GHSA-f4hj)', async () => {
    const jwt = String(ids.suspendedJwtCookie)
    const patch = await raw('PATCH', `/users/${idOf('suspended')}`, { jar: jwt, body: {} })
    expect(patch.status).toBe(401)
    const page = await raw('POST', '/pages', { jar: jwt, body: { title: 'nope' } })
    expect(page.status).toBe(401)
    const refresh = await raw('POST', '/users/refresh-token', { jar: jwt, body: {} })
    expect(refresh.status).toBe(401)
    // The authorization map carries no grant either.
    const perms = await accessOf({ jar: jwt })
    expect(perms.canAccessAdmin).toBeFalsy()
    expect(perms.usersUpdate).toBeFalsy()
  })

  it('api-key channel: refused on the next request', async () => {
    const key = { authorization: 'users API-Key suspended-api-key-0123456789abcdef' }
    const patch = await raw('PATCH', `/users/${idOf('suspended')}`, { ...key, body: {} })
    expect(patch.status).toBe(401)
    const page = await raw('POST', '/pages', { ...key, body: { title: 'nope' } })
    expect(page.status).toBe(401)
  })

  it('local login: refused by beforeLogin', async () => {
    const attempt = await login('suspended@test.dev', 'SuspendedKnown-1')
    expect(attempt.status).toBe(401)
  })

  it('forgot/reset-password: no usable credential', async () => {
    // forgot-password itself succeeds for the unlinked document (the
    // token goes to the user's own inbox) — but the reset is refused:
    // the reset operation runs beforeLogin with the found user.
    const forgot = await raw('POST', '/users/forgot-password', {
      body: { email: 'suspended@test.dev' },
    })
    expect(forgot.status).toBe(200)
    // Plant a FRESH token after the forgot (the real one is only in
    // the inbox) and drive the reset with it.
    await payload.update({
      collection: 'users',
      id: idOf('suspended'),
      data: {
        resetPasswordToken: 'suspended-reset-token-2',
        resetPasswordExpiration: TOKEN_EXPIRES,
      },
      overrideAccess: true,
    })
    const reset = await raw('POST', '/users/reset-password', {
      body: { token: 'suspended-reset-token-2', password: 'RotationKnows-1' },
    })
    expect(reset.status).toBe(401)
    const replant = await login('suspended@test.dev', 'RotationKnows-1')
    expect(replant.status).toBe(401)
  })

  // The GraphQL mutations (`loginUser`, `forgotPasswordUser`,
  // `resetPasswordUser`, `createPage`, …) resolve through the SAME
  // operation layer; integration-credential-paths-graphql.test.ts walks
  // them against Payload's real GraphQL schema (matrix row 11).
})

describe('provider-owned local credentials (GHSA-f4hj default)', () => {
  it('local login refused on a linked document', async () => {
    const attempt = await login('linked@test.dev', 'LinkedKnown-1')
    expect(attempt.status).toBe(403)
  })

  it('forgot-password refused on a linked document', async () => {
    const forgot = await raw('POST', '/users/forgot-password', {
      body: { email: 'linked@test.dev' },
    })
    expect(forgot.status).toBe(403)
    // No token was issued: the planted one is the only route, and it
    // is refused too.
    const reset = await raw('POST', '/users/reset-password', {
      body: { token: 'linked-reset-token', password: 'RotationKnows-2' },
    })
    expect(reset.status).toBe(403)
    const replant = await login('linked@test.dev', 'RotationKnows-2')
    // The reset was refused, so the password never rotated: the login
    // fails on credentials before any account control runs.
    expect(replant.status).toBe(401)
  })

  it('an operator account (no identities) keeps local credentials', async () => {
    const opened = await login('admin@test.dev', PASSWORD)
    expect(opened.status).toBe(200)
    const planted = await payload.update({
      collection: 'users',
      id: idOf('admin'),
      data: {
        resetPasswordToken: 'operator-reset-token',
        resetPasswordExpiration: TOKEN_EXPIRES,
      },
      overrideAccess: true,
    })
    void planted
    const reset = await raw('POST', '/users/reset-password', {
      body: { token: 'operator-reset-token', password: 'RotatedOperator-1' },
    })
    expect(reset.status).toBe(200)
    const rotated = await login('admin@test.dev', 'RotatedOperator-1')
    expect(rotated.status).toBe(200)
  })

  it('the Local API is gated the same way (overrideAccess is not a bypass)', async () => {
    await expect(
      payload.forgotPassword({ collection: 'users', data: { email: 'linked@test.dev' } })
    ).rejects.toThrow(/provider-linked/)
  })
})

describe('MFA policy on local credentials (GHSA-f4hj projection)', () => {
  it('local login succeeds; the policy role is withheld from authorization', async () => {
    const opened = await login('mfa@test.dev', 'MfaKnown-1')
    // Login itself is not blocked — the SESSION loses the role.
    expect(opened.status).toBe(200)
    const jwt = setCookieOf(opened.headers)
    const perms = await accessOf({ jar: jwt })
    // `auditor` is a manager role: without MFA proof the grant is
    // gone, not just the label.
    expect(perms.canAccessAdmin).toBeFalsy()
    const write = await raw('PATCH', `/users/${String(ids.mfa)}`, {
      jar: jwt,
      body: { roles: ['admin'] },
    })
    const body = write.body as { doc?: { roles?: string[] } }
    expect(body.doc?.roles).not.toEqual(['admin'])
  })

  it('provider session without MFA proof: withheld the same way', async () => {
    const jar = stub.issue({
      sessionId: 'sess-auditor-nomfa',
      providerUserId: 'auditor-linked-1',
      email: 'auditor-linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const session = await raw('GET', '/auth-link/session', { jar })
    expect(session.status).toBe(200)
    const body = session.body as { user: { roles: string[] } }
    expect(body.user.roles).not.toContain('auditor')
  })

  it('provider session WITH MFA proof: the role survives', async () => {
    const jar = stub.issue({
      sessionId: 'sess-auditor-mfa',
      providerUserId: 'auditor-linked-1',
      email: 'auditor-linked@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
      mfaSatisfied: true,
    })
    const session = await raw('GET', '/auth-link/session', { jar })
    expect(session.status).toBe(200)
    const body = session.body as { user: { roles: string[] } }
    expect(body.user.roles).toContain('auditor')
  })
})

describe('role governance and the linkable proof (unchanged controls)', () => {
  it('a non-manager cannot write roles over REST', async () => {
    const opened = await login('unproven@test.dev', 'AttackerKnows-1')
    expect(opened.status).toBe(200)
    const jar = setCookieOf(opened.headers)
    const write = await raw('PATCH', `/users/${String(ids.unproven)}`, {
      jar,
      body: { roles: ['admin'] },
    })
    const body = write.body as { doc?: { roles?: string[] } }
    expect(body.doc?.roles).not.toEqual(['admin'])
  })

  it('an unproven email never JIT-links', async () => {
    const jar = stub.issue({
      sessionId: 'sess-unproven',
      providerUserId: 'unproven-identity',
      email: 'unproven@test.dev',
      expiresAt: new Date(Date.now() + 3600_000),
    })
    const session = await raw('GET', '/auth-link/session', { jar })
    expect(session.status).toBe(401)
  })

  it('the engine keeps overrideAccess writes on a suspended document', async () => {
    const updated = await payload.update({
      collection: 'users',
      id: idOf('suspended'),
      data: { roles: ['user'] },
      overrideAccess: true,
    })
    expect(updated.roles).toEqual(['user'])
  })
})

describe('unlock (row 9)', () => {
  it('anonymous unlock is refused; a suspended JWT is refused by the row-4 gate', async () => {
    const anonymous = await raw('POST', '/users/unlock', { body: { email: 'unproven@test.dev' } })
    expect(anonymous.status).toBe(403)
    const suspended = await raw('POST', '/users/unlock', {
      jar: String(ids.suspendedJwtCookie),
      body: { email: 'unproven@test.dev' },
    })
    expect(suspended.status).toBe(401)
  })

  it('a plain signed-in user may not unlock (not even their own account)', async () => {
    const opened = await login('unproven@test.dev', 'AttackerKnows-1')
    expect(opened.status).toBe(200)
    const refused = await raw('POST', '/users/unlock', {
      jar: setCookieOf(opened.headers),
      body: { email: 'mfa@test.dev' },
    })
    expect(refused.status).toBe(403)
  })

  it('a role manager may unlock', async () => {
    await payload.create({
      collection: 'users',
      data: { email: 'unlocker@test.dev', password: PASSWORD, roles: ['admin'] },
      overrideAccess: true,
    })
    const opened = await login('unlocker@test.dev', PASSWORD)
    expect(opened.status).toBe(200)
    const unlocked = await raw('POST', '/users/unlock', {
      jar: setCookieOf(opened.headers),
      body: { email: 'unproven@test.dev' },
    })
    expect(unlocked.status).toBe(200)
  })
})
