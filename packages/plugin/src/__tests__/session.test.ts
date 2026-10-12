import { errAsync, okAsync, ResultAsync } from 'neverthrow'
import {
  createProviderRegistry,
  defineProviderId,
  defineSessionId,
  defineUserId,
  nullLogger,
  parseEmail,
  parseRole,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  systemClock,
  UnknownProviderError,
  UserExistsError,
  type Email,
  type IdentityProviderPort,
  type NewUser,
  type ProviderId,
  type ProviderSession,
  type Role,
  type UserId,
  type UserRecord,
  type UserRepository,
} from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import { createSessionService, type SessionServiceDeps } from '../session.js'

function email(value: string): Email {
  const parsed = parseEmail(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

function role(value: string): Role {
  const parsed = parseRole(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

function sessionFor(providerUserId: string, overrides?: Partial<ProviderSession>): ProviderSession {
  return {
    sessionId: `sess-${providerUserId}`,
    providerUserId,
    email: email(`${providerUserId}@test.dev`),
    emailVerified: true,
    expiresAt: new Date(Date.now() + 3600_000),
    ...overrides,
  }
}

type ProviderScript = ProviderSession | null | 'error'

/** Counting stub provider: records every `getSession` call for ordering assertions. */
function countingProvider(id: string, script: ProviderScript) {
  const providerId: ProviderId = defineProviderId(id)
  const calls: Headers[] = []
  const provider: IdentityProviderPort = {
    id: providerId,
    sessionCookieNames: [`al_${id}_session`],
    getSession: (headers) => {
      calls.push(headers)
      if (script === 'error') {
        return errAsync(new ProviderError(providerId, 'corrupt row'))
      }
      return okAsync(script)
    },
    revokeSession: () => okAsync(undefined),
  }
  return { provider, calls }
}

class FakeUserRepository implements UserRepository {
  private readonly users = new Map<string, UserRecord>()
  private nextId = 1

  findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError> {
    return okAsync(this.users.get(String(id)) ?? null)
  }

  findByEmail(target: Email): ResultAsync<UserRecord | null, RepositoryError> {
    for (const user of this.users.values()) {
      if (user.email === target) {
        return okAsync(user)
      }
    }
    return okAsync(null)
  }

  findByProviderIdentity(ref: {
    providerId: ProviderId
    providerUserId: string
  }): ResultAsync<UserRecord | null, RepositoryError> {
    for (const user of this.users.values()) {
      if (
        user.identities.some(
          (identity) =>
            identity.providerId === ref.providerId && identity.providerUserId === ref.providerUserId
        )
      ) {
        return okAsync(user)
      }
    }
    return okAsync(null)
  }

  create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
    const now = new Date()
    const user: UserRecord = {
      id: defineUserId(String(this.nextId++)),
      email: input.email,
      roles: [...input.roles],
      identities:
        input.identity === undefined
          ? []
          : [{ ...input.identity, email: input.email, linkedAt: now }],
      createdAt: now,
      updatedAt: now,
    }
    this.users.set(String(user.id), user)
    return okAsync(user)
  }

  linkIdentity(): ResultAsync<UserRecord, RepositoryError> {
    throw new Error('not exercised by failover tests')
  }

  setRoles(): ResultAsync<UserRecord, RepositoryError> {
    throw new Error('not exercised by failover tests')
  }

  setEmail(): ResultAsync<UserRecord, RepositoryError> {
    throw new Error('not exercised by failover tests')
  }
}

/**
 * Repository losing a JIT create race: the first identity read misses
 * (the use-case's lookup — the service no longer pre-reads), `create`
 * reports the lost race, and later reads see the winner's link — or
 * nothing, when there is no winner.
 */
class RacingUserRepository extends FakeUserRepository {
  private reads = 0

  constructor(private readonly winner: UserRecord | null) {
    super()
  }

  override findByProviderIdentity(): ResultAsync<UserRecord | null, RepositoryError> {
    this.reads += 1
    if (this.reads <= 1) {
      return okAsync(null)
    }
    return okAsync(this.winner)
  }

  override create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
    return errAsync(new UserExistsError(input.email))
  }
}

function depsFor(...providers: IdentityProviderPort[]): SessionServiceDeps {
  return depsWithUsers(new FakeUserRepository(), ...providers)
}

/** Repository counting reads: proves single-read verification (ARCH-8). */
class CountingUserRepository extends FakeUserRepository {
  identityReads = 0
  emailReads = 0

  override findByEmail(target: Email): ResultAsync<UserRecord | null, RepositoryError> {
    this.emailReads += 1
    return super.findByEmail(target)
  }

  override findByProviderIdentity(ref: {
    providerId: ProviderId
    providerUserId: string
  }): ResultAsync<UserRecord | null, RepositoryError> {
    this.identityReads += 1
    return super.findByProviderIdentity(ref)
  }
}

function depsWithUsers(
  users: UserRepository,
  ...providers: IdentityProviderPort[]
): SessionServiceDeps {
  const registry = createProviderRegistry()
  for (const provider of providers) {
    const registered = registry.register(provider)
    if (registered.isErr()) {
      throw registered.error
    }
  }
  return {
    users,
    registry,
    logger: nullLogger(),
    clock: systemClock(),
    defaultRoles: [role('user')],
  }
}

describe('session failover', () => {
  it('short-circuits on the first provider holding a session', async () => {
    const first = countingProvider('first', sessionFor('u-first'))
    const second = countingProvider('second', sessionFor('u-second'))
    const sessions = createSessionService(depsFor(first.provider, second.provider))

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.providerId).toBe(first.provider.id)
    }
    expect(first.calls).toHaveLength(1)
    // The secondary is never touched: no exhaustion, no call.
    expect(second.calls).toHaveLength(0)
  })

  it('falls through to the secondary only after the first is exhausted', async () => {
    const first = countingProvider('first', null)
    const second = countingProvider('second', sessionFor('u-second'))
    const sessions = createSessionService(depsFor(first.provider, second.provider))

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.providerId).toBe(second.provider.id)
    }
    expect(first.calls).toHaveLength(1)
    expect(second.calls).toHaveLength(1)
  })

  it('skips a corrupt provider without killing its healthy sibling', async () => {
    const corrupt = countingProvider('corrupt', 'error')
    const healthy = countingProvider('healthy', sessionFor('u-healthy'))
    const sessions = createSessionService(depsFor(corrupt.provider, healthy.provider))

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.providerId).toBe(healthy.provider.id)
      expect(result.value.userId).toBeDefined()
    }
    expect(corrupt.calls).toHaveLength(1)
    expect(healthy.calls).toHaveLength(1)
  })

  it('succeeds via the working provider while warning on the failing one', async () => {
    const warn = vi.fn()
    const logger = { ...nullLogger(), warn }
    const failing = countingProvider('failing', 'error')
    const working = countingProvider('working', sessionFor('u-working'))
    const registry = createProviderRegistry()
    for (const provider of [failing.provider, working.provider]) {
      const registered = registry.register(provider)
      if (registered.isErr()) {
        throw registered.error
      }
    }
    const sessions = createSessionService({
      users: new FakeUserRepository(),
      registry,
      logger,
      clock: systemClock(),
      defaultRoles: [role('user')],
    })

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.providerId).toBe(working.provider.id)
    }
    expect(failing.calls).toHaveLength(1)
    expect(working.calls).toHaveLength(1)
    expect(warn).toHaveBeenCalledWith('provider session read failed', { providerId: 'failing' })
  })

  it('terminates a three-provider chain on the last session', async () => {
    const first = countingProvider('first', null)
    const second = countingProvider('second', 'error')
    const third = countingProvider('third', sessionFor('u-third'))
    const sessions = createSessionService(depsFor(first.provider, second.provider, third.provider))

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.providerId).toBe(third.provider.id)
    }
    expect(first.calls).toHaveLength(1)
    expect(second.calls).toHaveLength(1)
    expect(third.calls).toHaveLength(1)
  })

  it('terminates with SessionInvalidError when no provider holds a session', async () => {
    const first = countingProvider('first', null)
    const second = countingProvider('second', 'error')
    const third = countingProvider('third', null)
    const sessions = createSessionService(depsFor(first.provider, second.provider, third.provider))

    const result = await sessions.verify(new Headers())
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(SessionInvalidError)
      expect(result.error).not.toBeInstanceOf(SessionExpiredError)
    }
    expect(first.calls).toHaveLength(1)
    expect(second.calls).toHaveLength(1)
    expect(third.calls).toHaveLength(1)
  })

  it('retries the read once after losing a JIT create race', async () => {
    const now = new Date()
    const winner: UserRecord = {
      id: defineUserId('winner-1'),
      email: email('racer@test.dev'),
      roles: [role('user')],
      identities: [],
      createdAt: now,
      updatedAt: now,
    }
    const racer = countingProvider('racer', sessionFor('u-racer', { email: winner.email }))
    const sessions = createSessionService(
      depsWithUsers(new RacingUserRepository(winner), racer.provider)
    )

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.userId).toBe(winner.id)
      expect(result.value.providerId).toBe(racer.provider.id)
    }
  })

  it('fails closed when the race retry finds no link', async () => {
    const racer = countingProvider('racer', sessionFor('u-racer'))
    const sessions = createSessionService(
      depsWithUsers(new RacingUserRepository(null), racer.provider)
    )

    const result = await sessions.verify(new Headers())
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(SessionInvalidError)
      expect(result.error.message).toBe('Session is invalid: session has no linked user')
    }
  })

  it('reads the repository once per verification on the linked path', async () => {
    const users = new CountingUserRepository()
    const created = await users.create({
      email: email('linked@test.dev'),
      roles: [role('user')],
      identity: { providerId: defineProviderId('solo'), providerUserId: 'u-solo' },
    })
    if (created.isErr()) {
      throw created.error
    }
    const solo = countingProvider('solo', sessionFor('u-solo', { email: email('linked@test.dev') }))
    const sessions = createSessionService(depsWithUsers(users, solo.provider))

    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    // The use-case's identity lookup is the only read: no service
    // pre-read, no email fallback on a linked match.
    expect(users.identityReads).toBe(1)
    expect(users.emailReads).toBe(0)
  })

  it('warns (once per corrupt provider) instead of throwing', async () => {
    const warn = vi.fn()
    const logger = { ...nullLogger(), warn }
    const corrupt = countingProvider('corrupt', 'error')
    const registry = createProviderRegistry()
    const registered = registry.register(corrupt.provider)
    if (registered.isErr()) {
      throw registered.error
    }
    const sessions = createSessionService({
      users: new FakeUserRepository(),
      registry,
      logger,
      clock: systemClock(),
      defaultRoles: [role('user')],
    })
    const result = await sessions.verify(new Headers())
    expect(result.isErr()).toBe(true)
    expect(warn).toHaveBeenCalledWith('provider session read failed', { providerId: 'corrupt' })
  })
})

describe('session revoke', () => {
  it('revokes through the owning provider', async () => {
    const solo = countingProvider('solo', null)
    const sessions = createSessionService(depsFor(solo.provider))
    const revoked = await sessions.revoke({
      id: defineSessionId('s-1'),
      userId: defineUserId('u-1'),
      providerId: solo.provider.id,
      expiresAt: new Date(Date.now() + 60_000),
    })
    expect(revoked.isOk()).toBe(true)
  })

  it('returns UnknownProviderError for an unregistered provider (logout 500 path)', async () => {
    const solo = countingProvider('solo', null)
    const sessions = createSessionService(depsFor(solo.provider))
    const revoked = await sessions.revoke({
      id: defineSessionId('s-1'),
      userId: defineUserId('u-1'),
      providerId: defineProviderId('removed'),
      expiresAt: new Date(Date.now() + 60_000),
    })
    expect(revoked._unsafeUnwrapErr()).toBeInstanceOf(UnknownProviderError)
  })
})
