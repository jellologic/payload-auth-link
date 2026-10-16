/**
 * Two adjacent paths found re-validating GHSA-f4hj-hm2r-28ww and
 * GHSA-98hq-hh6v-2p2r:
 *
 * - `roleValues` + a LOCAL session: Payload's local JWT carries the
 *   STORED role values, so the MFA-policy strip and the role-manager
 *   check have to compare canonically. Before the fix, a local
 *   `AUDITOR` kept the policy role (and a local `ADMIN` was no
 *   manager).
 * - users-collection versions: Payload's `readVersions` default
 *   (any signed-in user) listed every user's versions, emails
 *   included, past the self-only `read` default.
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
const SECRET = 'local-roles-versions-secret-32!'
const PASSWORD = 'correct-horse-battery'

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider({ capabilities: ['mfa'] })

type Response = { status: number; body: unknown; headers: Headers }

async function raw(method: string, path: string, jar?: string): Promise<Response> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    origin: ORIGIN,
  }
  if (jar !== undefined) {
    headers.cookie = jar
  }
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, { method, headers }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body, headers: response.headers }
}

async function login(email: string): Promise<string> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/users/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ email, password: PASSWORD }),
    }),
  })
  expect(response.status).toBe(200)
  return (response.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
}

const rolesOf = (user: unknown): unknown =>
  typeof user === 'object' && user !== null ? (user as { roles?: unknown }).roles : undefined

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' }, push: true }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      { slug: 'users', auth: true, versions: true, fields: [] },
      {
        slug: 'reports',
        // A host gating on the STORED value, as `projectRolesAs:
        // 'stored'` invites.
        access: {
          read: ({ req }) => {
            const roles = rolesOf(req.user)
            return Array.isArray(roles) && roles.includes('AUDITOR')
          },
        },
        fields: [{ name: 'title', type: 'text' }],
      },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user', 'auditor'],
        defaultRole: 'user',
        roleValues: { admin: 'ADMIN', auditor: 'AUDITOR' },
        projectRolesAs: 'stored',
        roleManagerRoles: ['admin', 'auditor'],
        policies: { requireMfaForRoles: ['auditor'] },
        providers: [stub.provider],
      }),
    ],
  })
  payload = await getPayload({ config })
  for (const [email, roles] of [
    ['admin@test.dev', ['ADMIN']],
    ['auditor@test.dev', ['user', 'AUDITOR']],
    ['plain@test.dev', ['user']],
    ['other@test.dev', ['user']],
  ] as const) {
    await payload.create({
      collection: 'users',
      data: { email, password: PASSWORD, roles: [...roles] },
      overrideAccess: true,
    })
  }
  await payload.create({ collection: 'reports', data: { title: 'q3' }, overrideAccess: true })
}, 60_000)

describe('roleValues on a local session: governance compares canonically', () => {
  it('the MFA-policy role is withheld from a local session holding its stored value', async () => {
    const jar = await login('auditor@test.dev')
    const reports = await raw('GET', '/reports', jar)
    expect(reports.status).toBe(403)
    const access = await raw('GET', '/access', jar)
    expect((access.body as { canAccessAdmin?: boolean }).canAccessAdmin).toBeFalsy()
  })

  it('a local admin holding the stored manager value is a role manager', async () => {
    const jar = await login('admin@test.dev')
    const access = await raw('GET', '/access', jar)
    expect((access.body as { canAccessAdmin?: boolean }).canAccessAdmin).toBe(true)
    const users = await raw('GET', '/users?limit=10', jar)
    expect((users.body as { totalDocs?: number }).totalDocs).toBe(4)
  })
})

describe('users versions are not an enumeration channel', () => {
  it('a plain user cannot list user versions', async () => {
    const jar = await login('plain@test.dev')
    // The self-only read default holds for the documents themselves…
    const own = await raw('GET', '/users?limit=10', jar)
    expect((own.body as { totalDocs?: number }).totalDocs).toBe(1)
    // …and versions carry no grant at all.
    const versions = await raw('GET', '/users/versions?limit=10', jar)
    expect(versions.status).toBe(403)
    expect(JSON.stringify(versions.body)).not.toContain('other@test.dev')
  })

  it('role managers still read user versions', async () => {
    const jar = await login('admin@test.dev')
    const versions = await raw('GET', '/users/versions?limit=10', jar)
    expect(versions.status).toBe(200)
    expect((versions.body as { totalDocs?: number }).totalDocs).toBeGreaterThan(0)
  })
})
