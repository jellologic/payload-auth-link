import { errAsync, okAsync, ResultAsync } from 'neverthrow'
import {
  ChannelNotAdmittedError,
  createProviderRegistry,
  defineProviderId,
  defineSessionId,
  defineUserId,
  nullLogger,
  parseEmail,
  parsePhoneNumber,
  parseRole,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  systemClock,
  UnknownProviderError,
  UserExistsError,
  UserSuspendedError,
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
  const claimEmail =
    overrides?.identity?.email?.value ?? overrides?.email ?? email(`${providerUserId}@test.dev`)
  const claimVerified = overrides?.identity?.email?.verified ?? overrides?.emailVerified ?? true
  return {
    sessionId: `sess-${providerUserId}`,
    providerUserId,
    email: claimEmail,
    emailVerified: claimVerified,
    expiresAt: new Date(Date.now() + 3600_000),
    identity: {
      email: { value: claimEmail, verified: claimVerified },
      phone: null,
      anonymous: false,
    },
    assurance: { methods: 'unknown', mfa: 'unknown' },
    actor: null,
    organizationId: null,
    channel: 'cookie',
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
    capabilities: new Set(),
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

  linkIdentity(
    userId: UserId,
    ref: { providerId: ProviderId; providerUserId: string }
  ): ResultAsync<UserRecord, RepositoryError> {
    void userId
    void ref
    throw new Error('not exercised by failover tests')
  }

  unlinkIdentity(): ResultAsync<UserRecord, RepositoryError> {
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
      expect(result.error.message).toBe(
        'Session is invalid: email already held by a document not proven to own it'
      )
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

describe('impersonation audit (CAP-8a)', () => {
  function serviceWithInfo(script: ProviderScript) {
    const info = vi.fn()
    const warn = vi.fn()
    const logger = { ...nullLogger(), info, warn }
    const solo = countingProvider('solo', script)
    const sessions = createSessionService({ ...depsFor(solo.provider), logger })
    return { info, warn, sessions }
  }

  it('audit-logs actor and target ids when an impersonated session verifies', async () => {
    const { info, sessions } = serviceWithInfo(
      sessionFor('u-target', { actor: { providerUserId: 'u-operator' } })
    )
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(info).toHaveBeenCalledWith('impersonated session used', {
        providerId: 'solo',
        actorProviderUserId: 'u-operator',
        // The operator has no linked Payload user in this repo:
        // provider-only, never dressed up as a Payload id (CAP-8b).
        actorKind: 'provider-only',
        targetProviderUserId: 'u-target',
        targetUserId: String(result.value.userId),
      })
    }
  })

  it('warns when the actor has no linked Payload user (CAP-8b fail-closed)', async () => {
    const { warn, sessions } = serviceWithInfo(
      sessionFor('u-target', { actor: { providerUserId: 'u-ghost-operator' } })
    )
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.actor).toEqual({
        kind: 'provider-only',
        providerUserId: 'u-ghost-operator',
      })
      expect(warn).toHaveBeenCalledWith('impersonated session actor has no linked Payload user', {
        providerId: 'solo',
        actorProviderUserId: 'u-ghost-operator',
        targetUserId: String(result.value.userId),
      })
    }
  })

  it('resolves the actor to the Payload user id when linked (CAP-8b)', async () => {
    const users = new FakeUserRepository()
    const operator = await users.create({
      email: email('operator@test.dev'),
      roles: [role('user')],
      identity: { providerId: defineProviderId('solo'), providerUserId: 'u-operator' },
    })
    if (operator.isErr()) {
      throw operator.error
    }
    const info = vi.fn()
    const solo = countingProvider(
      'solo',
      sessionFor('u-target', { actor: { providerUserId: 'u-operator' } })
    )
    const sessions = createSessionService({
      ...depsWithUsers(users, solo.provider),
      logger: { ...nullLogger(), info },
    })
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.actor).toEqual({
        kind: 'payload-user',
        providerUserId: 'u-operator',
        userId: operator.value.id,
      })
      expect(info).toHaveBeenCalledWith('impersonated session used', {
        providerId: 'solo',
        actorProviderUserId: 'u-operator',
        actorKind: 'payload-user',
        actorUserId: String(operator.value.id),
        targetProviderUserId: 'u-target',
        targetUserId: String(result.value.userId),
      })
    }
  })

  it('does not audit-log plain or actor-null sessions', async () => {
    for (const script of [sessionFor('u-plain'), sessionFor('u-plain', { actor: null })]) {
      const { info, sessions } = serviceWithInfo(script)
      const result = await sessions.verify(new Headers())
      expect(result.isOk()).toBe(true)
      expect(info).not.toHaveBeenCalledWith(
        'impersonated session used',
        expect.anything() as unknown
      )
    }
  })
})

describe('session facts projection (PORT-4)', () => {
  it('carries assurance, actor, and organizationId from the provider session', async () => {
    const rich = countingProvider(
      'rich',
      sessionFor('u-rich', {
        assurance: { methods: ['passkey'], mfa: true },
        actor: { providerUserId: 'u-operator' },
        organizationId: 'org-1',
      })
    )
    const sessions = createSessionService(depsFor(rich.provider))
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.assurance).toEqual({ methods: ['passkey'], mfa: true })
      // CAP-8b: the operator is unlinked in this repo, so the actor
      // projects in distinct provider-only form.
      expect(result.value.actor).toEqual({
        kind: 'provider-only',
        providerUserId: 'u-operator',
      })
      expect(result.value.organizationId).toBe('org-1')
    }
  })

  it("keeps 'unknown' assurance and omits null actor/organizationId", async () => {
    const plain = countingProvider('plain', sessionFor('u-plain'))
    const sessions = createSessionService(depsFor(plain.provider))
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.assurance).toEqual({ methods: 'unknown', mfa: 'unknown' })
      expect(result.value).not.toHaveProperty('actor')
      expect(result.value).not.toHaveProperty('organizationId')
    }
  })
})

describe('identity claim gate (PORT-1)', () => {
  it('refuses an anonymous no-claim session via the use-case gate, not a service pre-check', async () => {
    const noClaim = countingProvider(
      'noclaim',
      sessionFor('u-noclaim', {
        emailVerified: true,
        identity: { email: null, phone: null, anonymous: true },
      })
    )
    const sessions = createSessionService(depsFor(noClaim.provider))
    const result = await sessions.verify(new Headers())
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(SessionInvalidError)
      expect(result.error.message).toContain('anonymous')
    }
  })

  it('refuses an unlinked no-claim session under the default policy (typed, 401)', async () => {
    const noClaim = countingProvider(
      'noclaim',
      sessionFor('u-noclaim', {
        identity: { email: null, phone: null, anonymous: false },
      })
    )
    const sessions = createSessionService(depsFor(noClaim.provider))
    const result = await sessions.verify(new Headers())
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(SessionInvalidError)
      expect(result.error.message).toContain('no email identity claim')
    }
  })

  it('verifies an email-less session through the already-linked fast path', async () => {
    const users = new FakeUserRepository()
    const created = await users.create({
      email: email('linked@test.dev'),
      roles: [role('user')],
      identity: { providerId: defineProviderId('noclaim'), providerUserId: 'u-noclaim' },
    })
    if (created.isErr()) {
      throw created.error
    }
    const noClaim = countingProvider(
      'noclaim',
      sessionFor('u-noclaim', {
        identity: { email: null, phone: null, anonymous: false },
      })
    )
    const sessions = createSessionService(depsWithUsers(users, noClaim.provider))
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.userId).toBe(created.value.id)
    }
  })

  it('refuses an anonymous session even when previously linked (D3)', async () => {
    const users = new FakeUserRepository()
    const created = await users.create({
      email: email('linked@test.dev'),
      roles: [role('user')],
      identity: { providerId: defineProviderId('anon'), providerUserId: 'u-anon' },
    })
    if (created.isErr()) {
      throw created.error
    }
    const anon = countingProvider(
      'anon',
      sessionFor('u-anon', {
        identity: { email: null, phone: null, anonymous: true },
      })
    )
    const sessions = createSessionService(depsWithUsers(users, anon.provider))
    const result = await sessions.verify(new Headers())
    expect(result._unsafeUnwrapErr()).toBeInstanceOf(SessionInvalidError)
  })

  it('reaches the verified-phone branch for an email-less session', async () => {
    const phone = parsePhoneNumber('+14155552671')
    if (phone.isErr()) {
      throw phone.error
    }
    class PhoneUserRepository extends FakeUserRepository {
      holder: UserRecord | null = null
      findByPhone(): ResultAsync<UserRecord | null, RepositoryError> {
        return okAsync(this.holder)
      }
      override linkIdentity(
        userId: UserId,
        ref: { providerId: ProviderId; providerUserId: string }
      ): ResultAsync<UserRecord, RepositoryError> {
        void ref
        return this.findById(userId).andThen((user) =>
          user === null ? errAsync(new RepositoryError('linkIdentity')) : okAsync(user)
        )
      }
    }
    const users = new PhoneUserRepository()
    const created = await users.create({
      email: email('holder@test.dev'),
      roles: [role('user')],
    })
    if (created.isErr()) {
      throw created.error
    }
    users.holder = created.value
    const phoneOnly = countingProvider(
      'phoneonly',
      sessionFor('u-phone', {
        identity: {
          email: null,
          phone: { value: phone.value, verified: true },
          anonymous: false,
        },
      })
    )
    const sessions = createSessionService({
      ...depsWithUsers(users, phoneOnly.provider),
      linkingPolicy: { kind: 'verified-email-or-phone' },
    })
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.userId).toBe(created.value.id)
    }
  })

  it('refuses an unverified email claim even when the deprecated alias is verified', async () => {
    const unverified = countingProvider(
      'unverified',
      sessionFor('u-unverified', {
        emailVerified: true,
        identity: {
          email: { value: email('u-unverified@test.dev'), verified: false },
          phone: null,
          anonymous: false,
        },
      })
    )
    const sessions = createSessionService(depsFor(unverified.provider))
    const result = await sessions.verify(new Headers())
    expect(result._unsafeUnwrapErr()).toBeInstanceOf(SessionInvalidError)
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

describe('session verify boundaries', () => {
  it('returns SessionInvalidError (not a throw) for an empty provider session id (TYP-6)', async () => {
    const empty = countingProvider('empty', sessionFor('u-empty', { sessionId: '' }))
    const sessions = createSessionService(depsFor(empty.provider))
    const result = await sessions.verify(new Headers())
    expect(result._unsafeUnwrapErr()).toBeInstanceOf(SessionInvalidError)
  })

  it('expires exactly at expiresAt with no skew leeway (PAR-9)', async () => {
    const now = new Date('2026-10-12T12:00:00.000Z')
    const clock = { now: () => now }
    const at = (offsetMs: number) =>
      countingProvider(
        'edge',
        sessionFor('u-edge', { expiresAt: new Date(now.getTime() + offsetMs) })
      )
    const verifyWith = async (offsetMs: number) =>
      createSessionService({ ...depsFor(at(offsetMs).provider), clock }).verify(new Headers())
    expect((await verifyWith(0))._unsafeUnwrapErr()).toBeInstanceOf(SessionExpiredError)
    expect((await verifyWith(-1))._unsafeUnwrapErr()).toBeInstanceOf(SessionExpiredError)
    expect((await verifyWith(1)).isOk()).toBe(true)
  })
})

describe('channel admission (CAP-13a)', () => {
  it('denies a bearer session by default with a typed error, before linking', async () => {
    const users = new CountingUserRepository()
    const warn = vi.fn()
    const bearer = countingProvider('bearer', sessionFor('u-bearer', { channel: 'bearer' }))
    const sessions = createSessionService({
      ...depsWithUsers(users, bearer.provider),
      logger: { ...nullLogger(), warn },
    })
    const result = await sessions.verify(new Headers())
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(ChannelNotAdmittedError)
      expect((result.error as ChannelNotAdmittedError).channel).toBe('bearer')
      expect((result.error as ChannelNotAdmittedError).admittedChannels).toEqual(['cookie'])
    }
    expect(warn).toHaveBeenCalledWith('provider session channel not admitted', {
      providerId: 'bearer',
      channel: 'bearer',
    })
    // No linking happened: a denied channel never reaches the repo,
    // so it cannot JIT-provision a Payload user.
    expect(users.identityReads).toBe(0)
    expect(users.emailReads).toBe(0)
  })

  it('admits a bearer session when the channel is admitted by policy', async () => {
    const bearer = countingProvider('bearer', sessionFor('u-bearer', { channel: 'bearer' }))
    const sessions = createSessionService({
      ...depsFor(bearer.provider),
      admitChannels: ['cookie', 'bearer'],
    })
    const result = await sessions.verify(new Headers())
    expect(result.isOk()).toBe(true)
  })

  it('still admits cookie sessions under the default policy', async () => {
    const cookie = countingProvider('cookie', sessionFor('u-cookie'))
    const sessions = createSessionService(depsFor(cookie.provider))
    expect((await sessions.verify(new Headers())).isOk()).toBe(true)
  })

  it('does not fall through to a later provider when the presenting channel is denied', async () => {
    const bearer = countingProvider('bearer', sessionFor('u-bearer', { channel: 'bearer' }))
    const second = countingProvider('second', sessionFor('u-second'))
    const sessions = createSessionService(depsFor(bearer.provider, second.provider))
    const result = await sessions.verify(new Headers())
    expect(result._unsafeUnwrapErr()).toBeInstanceOf(ChannelNotAdmittedError)
    expect(second.calls).toHaveLength(0)
  })
})

describe('suspension gate (CAP-7)', () => {
  class SuspendedUserRepository extends FakeUserRepository {
    constructor(private readonly until: Date) {
      super()
    }

    override create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
      return super.create(input).map((user) => ({ ...user, suspendedUntil: this.until }))
    }
  }

  it('refuses a suspended user with a typed error, including for JWT-style sessions', async () => {
    const until = new Date(Date.now() + 3600_000)
    const provider = countingProvider('susp', sessionFor('u-susp'))
    const sessions = createSessionService(
      depsWithUsers(new SuspendedUserRepository(until), provider.provider)
    )
    const result = await sessions.verify(new Headers())
    expect(result._unsafeUnwrapErr()).toBeInstanceOf(UserSuspendedError)
    expect((result._unsafeUnwrapErr() as UserSuspendedError).suspendedUntil).toEqual(until)
  })

  it('admits the user once the suspension has lapsed', async () => {
    const until = new Date(Date.now() - 1)
    const provider = countingProvider('lapsed', sessionFor('u-lapsed'))
    const sessions = createSessionService(
      depsWithUsers(new SuspendedUserRepository(until), provider.provider)
    )
    expect((await sessions.verify(new Headers())).isOk()).toBe(true)
  })
})

describe('SSO domain gate (CAP-15)', () => {
  it('refuses linking when the domain guard denies, links when it allows', async () => {
    const users = new CountingUserRepository()
    const provider = countingProvider('sso', sessionFor('u-sso'))
    const denied = createSessionService({
      ...depsWithUsers(users, provider.provider),
      ssoDomainAllowed: () => okAsync(false),
    })
    const refused = await denied.verify(new Headers())
    expect(refused.isErr()).toBe(true)
    // The gate ran before linking: no user was provisioned.
    expect(users.emailReads).toBe(0)

    const allowed = createSessionService({
      ...depsWithUsers(new FakeUserRepository(), provider.provider),
      ssoDomainAllowed: (providerId, email) =>
        okAsync(providerId === 'sso' && email === 'u-sso@test.dev'),
    })
    expect((await allowed.verify(new Headers())).isOk()).toBe(true)
  })
})

describe('throwing provider reads', () => {
  it('maps a rejected getSession to typed errors, never a throw', async () => {
    const base = countingProvider('thrower', null)
    const throwing: IdentityProviderPort = {
      ...base.provider,
      getSession: () => Promise.reject(new Error('provider exploded')) as never,
    }
    const sessions = createSessionService(depsFor(throwing))
    const verified = await sessions.verify(new Headers())
    expect(verified.isErr()).toBe(true)
    const guest = await sessions.guest?.(new Headers())
    expect(guest?.isErr()).toBe(true)
  })
})

describe('guest principal (CAP-10)', () => {
  const anonymousSession = sessionFor('guest-1', {
    identity: {
      email: { value: email('guest-1@test.dev'), verified: false },
      phone: null,
      anonymous: true,
    },
  })

  it('recognizes an anonymous session as a guest without provisioning a user', async () => {
    const users = new CountingUserRepository()
    const provider = countingProvider('anon', anonymousSession)
    const sessions = createSessionService(depsWithUsers(users, provider.provider))
    // Verify as a Payload user is refused (D3), but the guest is named.
    expect((await sessions.verify(new Headers())).isErr()).toBe(true)
    const guest = await sessions.guest?.(new Headers())
    expect(guest?._unsafeUnwrap()).toMatchObject({ id: 'guest-1', providerId: 'anon' })
  })

  it('returns no guest for an expired or non-admitted-channel anonymous session', async () => {
    const expired = countingProvider('anon-expired', {
      ...anonymousSession,
      expiresAt: new Date(Date.now() - 1000),
    })
    const expiredService = createSessionService(depsFor(expired.provider))
    expect((await expiredService.guest?.(new Headers()))?._unsafeUnwrap()).toBeNull()

    const bearerAnon = countingProvider('anon-bearer', {
      ...anonymousSession,
      channel: 'bearer',
    })
    const cookieOnly = createSessionService(depsFor(bearerAnon.provider))
    expect((await cookieOnly.guest?.(new Headers()))?._unsafeUnwrap()).toBeNull()
  })

  it('returns no guest for a regular or absent session', async () => {
    const provider = countingProvider('plain', sessionFor('u-plain'))
    const sessions = createSessionService(depsFor(provider.provider))
    expect((await sessions.guest?.(new Headers()))?._unsafeUnwrap()).toBeNull()
    const none = countingProvider('none', null)
    const empty = createSessionService(depsFor(none.provider))
    expect((await empty.guest?.(new Headers()))?._unsafeUnwrap()).toBeNull()
  })
})
