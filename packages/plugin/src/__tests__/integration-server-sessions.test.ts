/**
 * Integration test: the supported server session API (issue #54).
 * `authLinkServer(payload)` mints, lists, and revokes sessions
 * through the provider port — never through BA internals — with the
 * suspension gate, the MFA projection, and the audit sink all
 * applied. Server session creation is gated by `allowServerSessions`.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { nullLogger } from '@payload-auth-link/core'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildConfig, getPayload, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  authLink,
  authLinkServer,
  AuthLinkServerMissingError,
  ServerSessionsDisabledError,
  UserSuspendedError,
} from '../index.js'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createServices } from '../services.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'server-sessions-secret-32-chars'

const dir = mkdtempSync(join(tmpdir(), 'pal-server-sessions-'))
const stub = createStubProvider()

function optionsWith(
  overrides: Partial<AuthLinkPluginOptions> & { logger?: AuthLinkPluginOptions['logger'] }
): AuthLinkPluginOptions {
  return {
    baseUrl: ORIGIN,
    roles: ['user', 'admin'],
    defaultRole: 'user',
    roleManagerRoles: ['admin'],
    providers: [stub.provider],
    logger: nullLogger(),
    ...overrides,
  }
}

async function boot(key: string, options: AuthLinkPluginOptions): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    // One shared SQLite file: sequential Payload instances in one
    // process each run push, and the later instance's push on a fresh
    // file can race its own init; the shared file is the pattern the
    // other multi-boot suites use.
    db: sqliteAdapter({ client: { url: `file:${join(dir, 'shared.db')}` }, push: true }),
    collections: [{ slug: 'pages', fields: [{ name: 'title', type: 'text' }] }],
    plugins: [authLink(options)],
  })
  return getPayload({ config, key })
}

async function seedUser(
  payload: Payload,
  email: string,
  roles: readonly string[] = ['user']
): Promise<{ id: string; providerUserId: string }> {
  const { parseEmail, parseRole, defineProviderId } = await import('@payload-auth-link/core')
  const services = createServices(wireOptions(optionsWith({})), payload)
  const parsedEmail = parseEmail(email)
  expect(parsedEmail.isOk()).toBe(true)
  if (parsedEmail.isErr()) {
    throw new Error('unreachable')
  }
  const rolesParsed = roles.map((role) => {
    const parsed = parseRole(role)
    expect(parsed.isOk()).toBe(true)
    if (parsed.isErr()) {
      throw new Error('unreachable')
    }
    return parsed.value
  })
  const created = await services.users.create({ email: parsedEmail.value, roles: rolesParsed })
  expect(created.isOk(), created.isErr() ? 'create failed' : 'ok').toBe(true)
  if (!created.isOk()) {
    throw new Error('unreachable')
  }
  // Link a stub-provider identity: server sessions are minted for the
  // PROVIDER user, reached through this link.
  const providerUserId = `stub-${String(created.value.id)}`
  const linked = await services.users.linkIdentity(created.value.id, {
    providerId: defineProviderId('stub'),
    providerUserId,
  })
  expect(linked.isOk(), linked.isErr() ? 'link failed' : 'ok').toBe(true)
  const reread = await services.users.findById(created.value.id)
  if (reread.isOk() && reread.value) {
    process.stdout.write(
      'DEBUG identities=' + JSON.stringify(reread.value.identities) + String.fromCharCode(10)
    )
  }
  if (!linked.isOk()) {
    throw new Error('unreachable')
  }
  return { id: created.value.id, providerUserId }
}

afterAll(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('authLinkServer (issue #54)', () => {
  // One shared boot: sequential Payload instances in one process hold
  // process-global SQLite/driver state that breaks later instances.
  let payload: Payload
  beforeAll(async () => {
    payload = await boot(
      'srv-a',
      optionsWith({
        onAudit: (event) => {
          auditEvents.push(event)
        },
      })
    )
  }, 120_000)

  const auditEvents: { message: string; fields: Record<string, unknown> }[] = []

  it('mints a session, resolves it via getSession, and audits the mint', async () => {
    const user = await seedUser(payload, 'mint@test.dev')
    const server = authLinkServer(payload)
    const created = await server.createSessionFor(user.id, {
      reason: 'dev-auto-login',
      actor: 'test-runner',
      ttlSeconds: 3600,
    })
    expect(created.sessionId).toBeTruthy()
    expect(created.token).toBeTruthy()
    expect(created.setCookie).toContain('al_stub_session=')
    // The minted session resolves through getSession — same rules as
    // the strategy.
    const headers = new Headers({ cookie: `al_stub_session=${created.token}` })
    const sessionUser = await server.getSession(headers)
    expect(sessionUser?.id).toBe(String(user.id))
    expect(sessionUser?.roles).toEqual(['user'])
    // The audit event carries reason + actor.
    const mintEvent = auditEvents.find((event) => event.message === 'server session created')
    expect(mintEvent?.fields.reason).toBe('dev-auto-login')
    expect(mintEvent?.fields.actor).toBe('test-runner')
  })

  it('refuses minting for suspended users', async () => {
    const user = await seedUser(payload, 'suspended@test.dev')
    await payload.update({
      collection: 'users',
      id: user.id,
      data: { suspendedUntil: new Date(Date.now() + 86_400_000).toISOString() },
      overrideAccess: true,
    })
    const server = authLinkServer(payload)
    await expect(server.createSessionFor(user.id, { reason: 'test' })).rejects.toBeInstanceOf(
      UserSuspendedError
    )
  })

  it('honors allowServerSessions: false', async () => {
    const payloadDisabled = await boot('srv-c', optionsWith({ allowServerSessions: false }))
    const userC = await seedUser(payloadDisabled, 'disabled@test.dev')
    await expect(
      authLinkServer(payloadDisabled).createSessionFor(userC.id, { reason: 'test' })
    ).rejects.toBeInstanceOf(ServerSessionsDisabledError)
  })

  it("'dev-only' (the default) mints on a non-production runtime", async () => {
    const user = await seedUser(payload, 'devonly@test.dev')
    const minted = await authLinkServer(payload).createSessionFor(user.id, { reason: 'dev' })
    expect(minted.token).toBeTruthy()
  })

  it('lists and revokes sessions', async () => {
    const user = await seedUser(payload, 'lister@test.dev')
    const server = authLinkServer(payload)
    const first = await server.createSessionFor(user.id, { reason: 'one', ttlSeconds: 3600 })
    const second = await server.createSessionFor(user.id, { reason: 'two', ttlSeconds: 3600 })
    const sessions = await server.listSessions(user.id)
    expect(sessions.map((session) => session.sessionId).sort()).toEqual(
      [first.sessionId, second.sessionId].sort()
    )
    await server.revokeSession(first.sessionId)
    const after = await server.listSessions(user.id)
    expect(after.map((session) => session.sessionId)).toEqual([second.sessionId])
    await server.revokeAllForUser(user.id)
    expect(await server.listSessions(user.id)).toEqual([])
  })

  it('throws a typed error when the plugin is not installed on the instance', async () => {
    const config = await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapter({ client: { url: `file:${join(dir, 'bare.db')}` }, push: true }),
      collections: [
        {
          slug: 'users',
          auth: true,
          fields: [{ name: 'email', type: 'email', required: true, index: true }],
        },
      ],
    })
    const bare = await getPayload({ config, key: 'srv-bare' })
    expect(() => authLinkServer(bare)).toBeInstanceOf(Function)
    expect(() => authLinkServer(bare)).toThrow(AuthLinkServerMissingError)
  })
})
