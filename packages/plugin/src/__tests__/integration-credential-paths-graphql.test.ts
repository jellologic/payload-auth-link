/**
 * Credential-path matrix over GraphQL (docs/security-model.md rows 3,
 * 4, 5, 6, 7, 9, 10, 11, 16, plus row 1's provider session): the
 * GraphQL mutations resolve through the SAME operation layer as REST,
 * so every account control must hold there too. This suite proves it
 * against Payload's real GraphQL schema (`@payloadcms/graphql`,
 * executed the way `@payloadcms/next`'s GRAPHQL_POST does: a
 * web-request-authenticated `req` in the context), not by
 * assertion. The REST walk lives in integration-credential-paths.
 */
import { configToSchema } from '@payloadcms/graphql'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { graphql, type GraphQLSchema } from 'graphql'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createWebRequest } from './payload-request.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'credential-paths-graphql-secret!'
const PASSWORD = 'correct-horse-battery'
const FUTURE = '2031-01-01T00:00:00.000Z'

let config: SanitizedConfig
let payload: Payload
let schema: GraphQLSchema
const stub = createStubProvider({ capabilities: ['mfa'] })
const ids: Record<string, string> = {}

type Channel = { jar?: string; authorization?: string }
type GqlResult = {
  data: Record<string, unknown> | null | undefined
  /** HTTP-equivalent status of the first error (Payload's `statusCode`). */
  status: number | undefined
  message: string | undefined
}

function headersFor(channel: Channel): Headers {
  const headers = new Headers({ 'content-type': 'application/json', origin: ORIGIN })
  if (channel.jar !== undefined) {
    headers.set('cookie', channel.jar)
  }
  if (channel.authorization !== undefined) {
    headers.set('authorization', channel.authorization)
  }
  return headers
}

async function gql(source: string, channel: Channel = {}): Promise<GqlResult> {
  const req = await createWebRequest({
    canSetHeaders: true,
    config,
    request: new Request(`${ORIGIN}/api/graphql`, {
      method: 'POST',
      headers: headersFor(channel),
      body: JSON.stringify({ query: source }),
    }),
  })
  const result = await graphql({ schema, source, contextValue: { req, headers: {} } })
  const first = result.errors?.[0]
  const original = first?.originalError as { status?: number } | undefined
  return {
    data: result.data as Record<string, unknown> | null | undefined,
    status: first === undefined ? undefined : (original?.status ?? 500),
    message: first?.message,
  }
}

async function restLogin(email: string, password: string): Promise<string> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/users/login`, {
      method: 'POST',
      headers: headersFor({}),
      body: JSON.stringify({ email, password }),
    }),
  })
  expect(response.status).toBe(200)
  return (response.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
}

function idOf(key: string): string {
  const value = ids[key]
  if (value === undefined) {
    throw new Error(`seed id missing: ${key}`)
  }
  return value
}

function identity(providerUserId: string, email: string) {
  return [{ providerId: 'stub', providerUserId, email, linkedAt: new Date().toISOString() }]
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
      { slug: 'users', auth: { useAPIKey: true, maxLoginAttempts: 5 }, fields: [] },
      { slug: 'pages', fields: [{ name: 'title', type: 'text', required: true }] },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user', 'auditor'],
        defaultRole: 'user',
        roleManagerRoles: ['admin', 'auditor'],
        policies: { requireMfaForRoles: ['auditor'] },
        providers: [stub.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  schema = configToSchema(config).schema
  const create = async (data: Record<string, unknown>): Promise<string> => {
    const doc = await payload.create({ collection: 'users', data, overrideAccess: true })
    return String(doc.id)
  }
  ids.admin = await create({ email: 'admin@test.dev', password: PASSWORD, roles: ['admin'] })
  ids.plain = await create({ email: 'plain@test.dev', password: 'PlainKnown-1', roles: ['user'] })
  ids.linked = await create({
    email: 'linked@test.dev',
    password: 'LinkedKnown-1',
    roles: ['user'],
    linkable: true,
    linkableEmail: 'linked@test.dev',
    identities: identity('linked-1', 'linked@test.dev'),
  })
  ids.suspended = await create({
    email: 'suspended@test.dev',
    password: 'SuspendedKnown-1',
    roles: ['user'],
  })
  ids.suspendedLinked = await create({
    email: 'suspended-linked@test.dev',
    password: 'SuspendedLinked-1',
    roles: ['user'],
    suspendedUntil: FUTURE,
    linkable: true,
    linkableEmail: 'suspended-linked@test.dev',
    identities: identity('suspended-linked-1', 'suspended-linked@test.dev'),
  })
  ids.mfa = await create({
    email: 'mfa@test.dev',
    password: 'MfaKnown-1',
    roles: ['user', 'auditor'],
  })
  // Credentials minted BEFORE the suspension lands (request-time gate).
  ids.suspendedJwt = await restLogin('suspended@test.dev', 'SuspendedKnown-1')
  await payload.update({
    collection: 'users',
    id: idOf('suspended'),
    data: {
      enableAPIKey: true,
      apiKey: 'gql-suspended-api-key-0123456789ab',
      resetPasswordToken: 'gql-suspended-reset',
      resetPasswordExpiration: FUTURE,
    },
    overrideAccess: true,
  })
  await payload.update({
    collection: 'users',
    id: idOf('linked'),
    data: { resetPasswordToken: 'gql-linked-reset', resetPasswordExpiration: FUTURE },
    overrideAccess: true,
  })
  await payload.update({
    collection: 'users',
    id: idOf('suspended'),
    data: { suspendedUntil: FUTURE },
    overrideAccess: true,
  })
}, 60_000)

/** The GraphQL Access query's admin grant (null when the field resolved no grant). */
async function canAccessAdmin(channel: Channel): Promise<boolean | null> {
  const result = await gql(`query { Access { canAccessAdmin } }`, channel)
  const access = result.data?.Access as { canAccessAdmin?: boolean | null } | null | undefined
  return access?.canAccessAdmin ?? null
}

const createPage = `mutation { createPage(data: { title: "nope" }) { id } }`

describe('GraphQL credential paths (rows 3–7, 9–11, 16)', () => {
  it('row 3: loginUsers refuses a suspended account (401) and a linked doc (403)', async () => {
    const suspended = await gql(
      `mutation { loginUser(email: "suspended@test.dev", password: "SuspendedKnown-1") { token } }`
    )
    expect(suspended.status).toBe(401)
    const linked = await gql(
      `mutation { loginUser(email: "linked@test.dev", password: "LinkedKnown-1") { token } }`
    )
    expect(linked.status).toBe(403)
    const operator = await gql(
      `mutation { loginUser(email: "admin@test.dev", password: "${PASSWORD}") { token } }`
    )
    expect(operator.status).toBeUndefined()
    expect((operator.data?.loginUser as { token?: unknown } | undefined)?.token).toBeTypeOf(
      'string'
    )
  })

  it('row 4: an existing local JWT is refused on the next GraphQL operation', async () => {
    const result = await gql(createPage, { jar: idOf('suspendedJwt') })
    expect(result.status).toBe(401)
  })

  it('row 5: refreshTokenUsers refuses a suspended JWT', async () => {
    const result = await gql(`mutation { refreshTokenUser { refreshedToken } }`, {
      jar: idOf('suspendedJwt'),
    })
    expect(result.status).toBe(401)
  })

  it('row 6: forgotPasswordUsers refuses a linked document (403)', async () => {
    const result = await gql(`mutation { forgotPasswordUser(email: "linked@test.dev") }`)
    expect(result.status).toBe(403)
  })

  it('row 7: resetPasswordUsers refuses a linked doc (403) and a suspended doc (401)', async () => {
    const linked = await gql(
      `mutation { resetPasswordUser(token: "gql-linked-reset", password: "Rotated-1") { token } }`
    )
    expect(linked.status).toBe(403)
    const suspended = await gql(
      `mutation { resetPasswordUser(token: "gql-suspended-reset", password: "Rotated-2") { token } }`
    )
    expect(suspended.status).toBe(401)
    // Refused BEFORE the write: the token is unspent and the
    // password unchanged (issue #86 — Payload writes before beforeLogin).
    // Raw read: the reset fields are hidden from the operation layer.
    const stored: unknown = await payload.db.findOne({
      collection: 'users',
      where: { id: { equals: idOf('suspended') } },
    })
    expect(stored).toMatchObject({ resetPasswordExpiration: FUTURE })
  })

  it('row 9: unlockUsers needs a session and runs the row-4 gate', async () => {
    const unlock = `mutation { unlockUser(email: "plain@test.dev") }`
    expect((await gql(unlock)).status).toBe(403)
    expect((await gql(unlock, { jar: idOf('suspendedJwt') })).status).toBe(401)
    const operatorJar = await restLogin('admin@test.dev', PASSWORD)
    const allowed = await gql(unlock, { jar: operatorJar })
    expect(allowed.status).toBeUndefined()
    expect(allowed.data?.unlockUser).toBe(true)
  })

  it('row 10: the API-key channel is refused on the next GraphQL operation', async () => {
    const result = await gql(createPage, {
      authorization: 'users API-Key gql-suspended-api-key-0123456789ab',
    })
    expect(result.status).toBe(401)
  })

  it('row 1 over GraphQL: a suspended provider session resolves no user', async () => {
    const jar = stub.issue({
      sessionId: 'gql-susp-linked',
      providerUserId: 'suspended-linked-1',
      email: 'suspended-linked@test.dev',
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    const result = await gql(createPage, { jar })
    expect([401, 403]).toContain(result.status)
    const me = await gql(`query { meUser { user { id } } }`, { jar })
    expect((me.data?.meUser as { user?: unknown } | undefined)?.user ?? null).toBeNull()
  })

  it('row 16: the Access query carries no admin grant for a suspended session', async () => {
    // Positive control: the operator's local session holds the grant.
    expect(await canAccessAdmin({ jar: await restLogin('admin@test.dev', PASSWORD) })).toBe(true)
    expect(await canAccessAdmin({ jar: idOf('suspendedJwt') })).not.toBe(true)
  })

  it('MFA projection: a local session holding a policy role loses the grant', async () => {
    const jar = await restLogin('mfa@test.dev', 'MfaKnown-1')
    // `auditor` is a manager role; without MFA proof it is withheld.
    expect(await canAccessAdmin({ jar })).not.toBe(true)
  })

  it('role governance: a non-manager cannot write roles through updateUser', async () => {
    const jar = await restLogin('plain@test.dev', 'PlainKnown-1')
    await gql(`mutation { updateUser(id: ${idOf('plain')}, data: { roles: [admin] }) { roles } }`, {
      jar,
    })
    const stored = await payload.findByID({
      collection: 'users',
      id: idOf('plain'),
      overrideAccess: true,
    })
    expect(stored.roles).toEqual(['user'])
  })
})
