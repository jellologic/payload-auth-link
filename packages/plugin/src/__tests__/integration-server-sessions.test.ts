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
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
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
        // The suite exercises the API surface; the gate itself has
        // dedicated tests. Explicit opt-in: the 'dev-only' default
        // mints ONLY on a development runtime, and vitest runs with
        // NODE_ENV='test'.
        allowServerSessions: true,
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

  it("'dev-only' (the default) mints ONLY on a development runtime", async () => {
    // The default used to enable minting on every runtime that merely
    // wasn't 'production' (CI, test, staging, unset) — a gate in name
    // only. Vitest runs with NODE_ENV='test': the default must now
    // REFUSE here, and only 'development' mints. Its own boot, so the
    // suite's explicit opt-in doesn't mask the gate.
    const payloadGate = await boot('srv-devgate', optionsWith({}))
    const user = await seedUser(payloadGate, 'devonly@test.dev')
    expect(process.env.NODE_ENV).not.toBe('development')
    await expect(
      authLinkServer(payloadGate).createSessionFor(user.id, { reason: 'dev' })
    ).rejects.toBeInstanceOf(ServerSessionsDisabledError)
  })

  it("'dev-only' mints on a development runtime", async () => {
    vi.stubEnv('NODE_ENV', 'development')
    try {
      const user = await seedUser(payload, 'devmint@test.dev')
      const minted = await authLinkServer(payload).createSessionFor(user.id, { reason: 'dev' })
      expect(minted.token).toBeTruthy()
    } finally {
      vi.unstubAllEnvs()
    }
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

  it('revokes sessions on every linked provider, not just the first (#72)', async () => {
    const providerA = createStubProvider({ id: 'stub-a' })
    const providerB = createStubProvider({ id: 'stub-b' })
    const twoProviders = [providerA.provider, providerB.provider]
    const payloadTwo = await boot('srv-two', optionsWith({ providers: twoProviders }))
    const { defineProviderId, parseEmail, parseRole } = await import('@payload-auth-link/core')
    const services = createServices(
      wireOptions(optionsWith({ providers: twoProviders })),
      payloadTwo
    )
    const parsedEmail = parseEmail('twolink@test.dev')
    if (parsedEmail.isErr()) {
      throw new Error('unreachable')
    }
    const rolesParsed = [parseRole('user')]
    const firstRole = rolesParsed[0]
    if (firstRole === undefined || firstRole.isErr()) {
      throw new Error('unreachable')
    }
    const created = await services.users.create({
      email: parsedEmail.value,
      roles: [firstRole.value],
    })
    if (!created.isOk()) {
      throw new Error('user create failed')
    }
    const linkedA = await services.users.linkIdentity(created.value.id, {
      providerId: defineProviderId('stub-a'),
      providerUserId: 'twolink-a',
    })
    const linkedB = await services.users.linkIdentity(created.value.id, {
      providerId: defineProviderId('stub-b'),
      providerUserId: 'twolink-b',
    })
    if (!linkedA.isOk() || !linkedB.isOk()) {
      throw new Error('identity link failed')
    }
    // Mint one session directly on EACH provider: createSessionFor
    // walks identities and stops at the first capable one, so only a
    // direct mint puts a live session on the second provider too.
    const expiresAt = new Date(Date.now() + 3_600_000)
    const mintA = await providerA.provider.createProviderSession?.('twolink-a', { expiresAt })
    const mintB = await providerB.provider.createProviderSession?.('twolink-b', { expiresAt })
    if (mintA === undefined || mintB === undefined) {
      throw new Error('providers cannot mint sessions')
    }
    if (mintA.isErr()) {
      throw new Error(mintA.error.message)
    }
    if (mintB.isErr()) {
      throw new Error(mintB.error.message)
    }
    const server = authLinkServer(payloadTwo)
    // listSessions walks EVERY linked provider (matching
    // revokeAllForUser), so the operator sees the whole picture.
    const listed = await server.listSessions(created.value.id)
    expect(listed.map((session) => session.sessionId).sort()).toEqual(
      [mintA.value.sessionId, mintB.value.sessionId].sort()
    )
    await server.revokeAllForUser(created.value.id)
    const leftA = providerA.provider.listProviderSessions?.('twolink-a')
    const leftB = providerB.provider.listProviderSessions?.('twolink-b')
    if (leftA === undefined || leftB === undefined) {
      throw new Error('providers cannot list sessions')
    }
    const listedA = await leftA
    const listedB = await leftB
    if (listedA.isErr() || listedB.isErr()) {
      throw new Error(
        listedA.isErr()
          ? listedA.error.message
          : (listedB as { error: { message: string } }).error.message
      )
    }
    expect(listedA.value).toEqual([])
    expect(listedB.value).toEqual([])
  })

  it('refuses sessionCookie when several cookie-transport providers are registered (#72)', async () => {
    const providerA = createStubProvider({ id: 'stub-a' })
    const providerB = createStubProvider({ id: 'stub-b' })
    const payloadTwo = await boot(
      'srv-cookie-ambiguity',
      optionsWith({ providers: [providerA.provider, providerB.provider] })
    )
    // The token does not name its provider, so the standalone
    // sessionCookie(token) cannot know whose secret/name to sign
    // with — refuse instead of silently signing with the wrong one.
    await expect(authLinkServer(payloadTwo).sessionCookie('some-token')).rejects.toThrow(
      /several registered providers mint cookie sessions/
    )
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
