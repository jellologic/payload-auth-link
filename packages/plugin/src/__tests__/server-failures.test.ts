/**
 * The server session API's failure contract (issue #54, #86): every
 * operation that cannot honour its claim THROWS — a revoke that
 * reached no provider, a partial revoke-all, an API-key verify with
 * no capable provider or a provider error, a mint/list on a user with
 * no capable linked identity. A silent pass here would tell an
 * operator a session was killed while it stays live.
 *
 * The user store is replaced with an in-memory fake (`createServices`
 * mocked) so each provider failure mode is driven exactly; the
 * Payload-backed happy paths live in integration-server-sessions.
 */
import {
  defineProviderId,
  nullLogger,
  parseEmail,
  parseRole,
  ProviderError,
  type ApiKeyVerification,
  type Capability,
  type Email,
  type IdentityProviderPort,
  type Role,
  type Session,
  type SessionId,
  type UserId,
  type UserRecord,
} from '@payload-auth-link/core'
import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import type { Payload } from 'payload'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import {
  authLinkServer,
  registerAuthLinkServer,
  ServerSessionUnsupportedError,
  UserSuspendedError,
} from '../server.js'
import { createStubProvider } from './stub-provider.js'

type FakeUsers = {
  readonly findById: (id: UserId) => ResultAsync<UserRecord | null, Error>
}
type FakeSessions = {
  readonly verify: (headers: Headers) => ResultAsync<Session | null, Error>
}

const services: { users: FakeUsers; sessions: FakeSessions } = {
  users: { findById: () => okAsync(null) },
  sessions: { verify: () => okAsync(null) },
}

vi.mock('../services.js', () => ({
  createServices: () => services,
}))

function email(value: string): Email {
  const parsed = parseEmail(value)
  if (parsed.isErr()) {
    throw new Error(`bad email ${value}`)
  }
  return parsed.value
}

function role(value: string): Role {
  const parsed = parseRole(value)
  if (parsed.isErr()) {
    throw new Error(`bad role ${value}`)
  }
  return parsed.value
}

function record(
  id: string,
  identities: readonly { providerId: string; providerUserId: string }[],
  extra: Partial<UserRecord> = {}
): UserRecord {
  const at = new Date('2026-01-01T00:00:00Z')
  return {
    id: id as UserId,
    email: email(`${id}@test.dev`),
    roles: [role('user')],
    identities: identities.map((identity) => ({
      providerId: defineProviderId(identity.providerId),
      providerUserId: identity.providerUserId,
      email: email(`${id}@test.dev`),
      linkedAt: at,
    })),
    createdAt: at,
    updatedAt: at,
    ...extra,
  }
}

function usersWith(...records: UserRecord[]): FakeUsers {
  return {
    findById: (id) => okAsync(records.find((candidate) => candidate.id === id) ?? null),
  }
}

/** A stub-provider port with selected methods overridden. */
function port(
  id: string,
  overrides: Partial<IdentityProviderPort> & { capabilities?: ReadonlySet<Capability> } = {}
): IdentityProviderPort {
  const base = createStubProvider({ id }).provider
  return { ...base, ...overrides }
}

const failing = (id: string, operation: string) => errAsync(new ProviderError(id, operation))

function serverFor(
  providers: readonly IdentityProviderPort[],
  extra: Partial<AuthLinkPluginOptions> = {}
) {
  const fakePayload = {} as Payload
  registerAuthLinkServer(
    fakePayload,
    wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'admin'],
      defaultRole: 'user',
      roleManagerRoles: ['admin'],
      providers: [...providers],
      logger: nullLogger(),
      allowServerSessions: true,
      ...extra,
    })
  )
  return authLinkServer(fakePayload)
}

const verification: ApiKeyVerification = {
  userId: 'provider-user-1',
  name: 'ci',
  start: 'pal_',
  prefix: null,
  metadata: null,
  rateLimitEnabled: null,
  rateLimitRemaining: null,
  expiresAt: null,
  permissions: null,
}

beforeEach(() => {
  services.users = { findById: () => okAsync(null) }
  services.sessions = { verify: () => okAsync(null) }
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('authLinkServer.revokeSession — fails loudly', () => {
  it('throws when EVERY provider refuses the revoke (no silent pass)', async () => {
    const server = serverFor([
      port('a', { revokeSession: () => failing('a', 'revokeSession') }),
      port('b', { revokeSession: () => failing('b', 'revokeSession') }),
    ])
    await expect(server.revokeSession('sess-1')).rejects.toThrow(
      /^revokeSession: Provider b failed during revokeSession$/
    )
  })

  it('resolves as soon as one provider revokes the handle', async () => {
    const revokeB = vi.fn(() => okAsync(undefined))
    const server = serverFor([
      port('a', { revokeSession: () => failing('a', 'revokeSession') }),
      port('b', { revokeSession: revokeB }),
    ])
    await expect(server.revokeSession('sess-2')).resolves.toBeUndefined()
    expect(revokeB).toHaveBeenCalledWith('sess-2')
  })
})

describe('authLinkServer.revokeAllForUser — fails closed', () => {
  it('throws on a PARTIAL failure, after still attempting every provider', async () => {
    const revokeA = vi.fn(() => failing('a', 'revokeUserSessions'))
    const revokeB = vi.fn(() => okAsync(undefined))
    services.users = usersWith(
      record('u1', [
        { providerId: 'a', providerUserId: 'pa' },
        { providerId: 'b', providerUserId: 'pb' },
      ])
    )
    const server = serverFor([
      port('a', { revokeUserSessions: revokeA }),
      port('b', { revokeUserSessions: revokeB }),
    ])
    await expect(server.revokeAllForUser('u1')).rejects.toThrow(
      'revokeAllForUser: a: Provider a failed during revokeUserSessions'
    )
    expect(revokeA).toHaveBeenCalledWith('pa')
    // The failure on `a` does not short-circuit `b`: every provider
    // is attempted so the maximum number of sessions dies.
    expect(revokeB).toHaveBeenCalledWith('pb')
  })

  it('reports EVERY failing provider', async () => {
    services.users = usersWith(
      record('u2', [
        { providerId: 'a', providerUserId: 'pa' },
        { providerId: 'b', providerUserId: 'pb' },
      ])
    )
    const server = serverFor([
      port('a', { revokeUserSessions: () => failing('a', 'x') }),
      port('b', { revokeUserSessions: () => failing('b', 'y') }),
    ])
    await expect(server.revokeAllForUser('u2')).rejects.toThrow(
      'revokeAllForUser: a: Provider a failed during x; b: Provider b failed during y'
    )
  })

  it('throws ServerSessionUnsupportedError when no linked provider can revoke', async () => {
    services.users = usersWith(
      record('u3', [
        // A provider no longer registered is skipped, not trusted.
        { providerId: 'gone', providerUserId: 'pg' },
        { providerId: 'a', providerUserId: 'pa' },
      ])
    )
    const server = serverFor([port('a', { capabilities: new Set<Capability>() })])
    const thrown = await server.revokeAllForUser('u3').catch((error: unknown) => error)
    expect(thrown).toBeInstanceOf(ServerSessionUnsupportedError)
    expect((thrown as Error).name).toBe('ServerSessionUnsupportedError')
    expect((thrown as Error).message).toBe(
      'user u3 has no linked identity whose provider supports revoke-user-sessions'
    )
  })

  it('throws when the capability is declared but the method is missing', async () => {
    services.users = usersWith(record('u4', [{ providerId: 'a', providerUserId: 'pa' }]))
    const server = serverFor([port('a', { revokeUserSessions: undefined })])
    await expect(server.revokeAllForUser('u4')).rejects.toBeInstanceOf(
      ServerSessionUnsupportedError
    )
  })

  it('throws for an unknown user and for a store error', async () => {
    const server = serverFor([port('a')])
    await expect(server.revokeAllForUser('nobody')).rejects.toThrow(
      'revokeAllForUser: no payload-auth-link user nobody'
    )
    services.users = { findById: () => errAsync(new Error('db down')) }
    await expect(server.revokeAllForUser(7)).rejects.toThrow(
      'revokeAllForUser: no payload-auth-link user 7'
    )
  })
})

describe('authLinkServer.verifyApiKey', () => {
  it('throws when no registered provider can verify API keys', async () => {
    const server = serverFor([port('a')])
    await expect(server.verifyApiKey('k')).rejects.toThrow(
      'verifyApiKey: the configured provider cannot verify API keys (capability api-key-verify)'
    )
  })

  it('throws when the capability is declared but verifyApiKey is missing', async () => {
    const server = serverFor([
      port('a', { capabilities: new Set<Capability>(['api-key-verify']), verifyApiKey: undefined }),
    ])
    await expect(server.verifyApiKey('k')).rejects.toThrow(/capability api-key-verify/)
  })

  it('throws on a provider error instead of reporting the key unknown', async () => {
    const server = serverFor([
      port('a', {
        capabilities: new Set<Capability>(['api-key-verify']),
        verifyApiKey: () => failing('a', 'verifyApiKey'),
      }),
    ])
    await expect(server.verifyApiKey('k')).rejects.toThrow(
      'verifyApiKey: Provider a failed during verifyApiKey'
    )
  })

  it('maps the provider verification through unchanged, and null for an unknown key', async () => {
    const verify = vi.fn((key: string) => okAsync(key === 'good' ? verification : null))
    const server = serverFor([
      port('plain'),
      port('keys', {
        capabilities: new Set<Capability>(['api-key-verify']),
        verifyApiKey: verify,
      }),
    ])
    await expect(server.verifyApiKey('good')).resolves.toEqual(verification)
    await expect(server.verifyApiKey('bad')).resolves.toBeNull()
    expect(verify).toHaveBeenCalledTimes(2)
  })
})

describe('authLinkServer.createSessionFor — refusal paths', () => {
  it('throws ServerSessionUnsupportedError when no linked identity can mint', async () => {
    services.users = usersWith(
      record('m1', [
        { providerId: 'gone', providerUserId: 'pg' },
        { providerId: 'a', providerUserId: 'pa' },
      ])
    )
    const server = serverFor([port('a', { createProviderSession: undefined })])
    const thrown = await server
      .createSessionFor('m1', { reason: 'test' })
      .catch((error: unknown) => error)
    expect(thrown).toBeInstanceOf(ServerSessionUnsupportedError)
    expect((thrown as Error).message).toBe(
      'user m1 has no linked identity whose provider supports server-session-create'
    )
  })

  it('throws when the provider refuses the mint', async () => {
    services.users = usersWith(record('m2', [{ providerId: 'a', providerUserId: 'pa' }]))
    const server = serverFor([
      port('a', { createProviderSession: () => failing('a', 'createProviderSession') }),
    ])
    await expect(server.createSessionFor('m2', { reason: 'test' })).rejects.toThrow(
      'createSessionFor: Provider a failed during createProviderSession'
    )
  })

  it('throws for an unknown user', async () => {
    const server = serverFor([port('a')])
    await expect(server.createSessionFor('ghost', { reason: 'test' })).rejects.toThrow(
      'createSessionFor: no payload-auth-link user ghost'
    )
  })

  it('refuses a suspended user but mints for a lapsed suspension', async () => {
    const future = new Date(Date.now() + 86_400_000)
    services.users = usersWith(
      record('s1', [{ providerId: 'a', providerUserId: 'pa' }], { suspendedUntil: future }),
      record('s2', [{ providerId: 'a', providerUserId: 'pb' }], {
        suspendedUntil: new Date(Date.now() - 86_400_000),
      })
    )
    const server = serverFor([port('a')])
    const refused = await server
      .createSessionFor('s1', { reason: 'test' })
      .catch((error: unknown) => error)
    expect(refused).toBeInstanceOf(UserSuspendedError)
    expect((refused as UserSuspendedError).suspendedUntil).toEqual(future)
    await expect(server.createSessionFor('s2', { reason: 'test' })).resolves.toMatchObject({
      sessionId: expect.any(String) as unknown,
    })
  })

  it('audits the REQUESTED expiry when the provider reports none, and omits setCookie for non-cookie providers', async () => {
    const audit: { message: string; fields: Record<string, unknown> }[] = []
    services.users = usersWith(record('m3', [{ providerId: 'a', providerUserId: 'pa' }]))
    const server = serverFor(
      [
        port('a', {
          createProviderSession: () =>
            okAsync({ sessionId: 'sid', token: 'tok', storedExpiresAt: null }),
          sessionCookie: undefined,
        }),
      ],
      { onAudit: (event) => void audit.push(event) }
    )
    const before = Date.now()
    const minted = await server.createSessionFor('m3', { reason: 'default-ttl', mfaProof: true })
    expect(minted.setCookie).toBeUndefined()
    // No ttl → the 7-day default.
    const sevenDays = 7 * 24 * 3600 * 1000
    expect(minted.expiresAt.getTime()).toBeGreaterThanOrEqual(before + sevenDays - 1000)
    expect(minted.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + sevenDays + 1000)
    const event = audit.find((entry) => entry.message === 'server session created')
    expect(event?.fields).toMatchObject({ reason: 'default-ttl', mfaProof: true, sessionId: 'sid' })
    expect(event?.fields).not.toHaveProperty('actor')
    expect(event?.fields.expiresAt).toBe(minted.expiresAt.toISOString())
  })
})

describe('authLinkServer.listSessions — refusal paths', () => {
  it('throws on a provider error, for an unknown user, and when no provider can list', async () => {
    services.users = usersWith(
      record('l1', [{ providerId: 'a', providerUserId: 'pa' }]),
      record('l2', [
        { providerId: 'gone', providerUserId: 'pg' },
        { providerId: 'b', providerUserId: 'pb' },
      ])
    )
    const server = serverFor([
      port('a', { listProviderSessions: () => failing('a', 'listProviderSessions') }),
      port('b', { listProviderSessions: undefined }),
    ])
    await expect(server.listSessions('l1')).rejects.toThrow(
      'listSessions: Provider a failed during listProviderSessions'
    )
    await expect(server.listSessions('nobody')).rejects.toThrow(
      'listSessions: no payload-auth-link user nobody'
    )
    await expect(server.listSessions('l2')).rejects.toBeInstanceOf(ServerSessionUnsupportedError)
  })
})

describe('authLinkServer.sessionCookie', () => {
  it('throws when no provider uses a cookie transport', async () => {
    const server = serverFor([port('a', { sessionCookie: undefined })])
    await expect(server.sessionCookie('tok')).rejects.toThrow(
      'sessionCookie: the configured provider does not use a cookie session transport'
    )
  })

  it("signs with the single cookie-transport provider's writer", async () => {
    const server = serverFor([port('a', { sessionCookie: undefined }), port('b')])
    await expect(server.sessionCookie('tok')).resolves.toBe(
      'al_stub_session=tok; Path=/; HttpOnly; SameSite=Lax'
    )
  })
})

describe('authLinkServer.getSession', () => {
  const session: Session = {
    id: 'sid' as SessionId,
    userId: 'g1' as UserId,
    providerId: defineProviderId('a'),
    expiresAt: new Date(Date.now() + 3_600_000),
  }

  it('returns null when verification fails, finds no session, or the user is gone', async () => {
    const server = serverFor([port('a')])
    services.sessions = { verify: () => errAsync(new Error('provider down')) }
    await expect(server.getSession(new Headers())).resolves.toBeNull()
    services.sessions = { verify: () => okAsync(null) }
    await expect(server.getSession(new Headers())).resolves.toBeNull()
    services.sessions = { verify: () => okAsync(session) }
    services.users = { findById: () => errAsync(new Error('db down')) }
    await expect(server.getSession(new Headers())).resolves.toBeNull()
  })

  it("projects stored role values when projectRolesAs is 'stored'", async () => {
    services.sessions = { verify: () => okAsync(session) }
    services.users = usersWith(
      record('g1', [{ providerId: 'a', providerUserId: 'pa' }], { roles: [role('admin')] })
    )
    const server = serverFor([port('a')], {
      projectRolesAs: 'stored',
      roleValues: { admin: 'ADMIN' },
    })
    const user = await server.getSession(new Headers())
    expect(user?.roles).toEqual(['ADMIN'])
    expect(user?.collection).toBe('users')
  })
})
