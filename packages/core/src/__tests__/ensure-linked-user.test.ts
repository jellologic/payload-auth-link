import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import { describe, expect, it } from 'vitest'
import { nullLogger, systemClock } from '../defaults.js'
import { parseEmail, type Email } from '../email.js'
import {
  RepositoryError,
  UnverifiedEmailError,
  UnverifiedIdentityError,
  UserExistsError,
} from '../errors.js'
import {
  defineProviderId,
  defineUserId,
  type NewUser,
  type ProviderIdentityRef,
  type ProviderProfile,
  type UserId,
  type UserRecord,
  type UserRepository,
  type LoggerPort,
} from '../ports.js'
import { parsePhoneNumber, type PhoneNumber } from '../phone.js'
import { parseRole, type Role } from '../roles.js'
import { ensureLinkedUser } from '../use-cases/ensure-linked-user.js'

function phone(value: string): PhoneNumber {
  const parsed = parsePhoneNumber(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

function phoneOnlyProfile(
  providerUserId: string,
  overrides?: { verified?: boolean; anonymous?: boolean }
): ProviderProfile {
  return profile({
    providerUserId,
    identity: {
      email: null,
      phone: { value: phone('+14155550132'), verified: overrides?.verified ?? true },
      anonymous: overrides?.anonymous ?? false,
    },
  })
}

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

function profile(
  overrides: Partial<ProviderProfile> & { providerUserId: string }
): ProviderProfile {
  const claimEmail =
    overrides.identity?.email?.value ?? overrides.email ?? email('user@example.com')
  const claimVerified = overrides.identity?.email?.verified ?? overrides.emailVerified ?? true
  return {
    email: claimEmail,
    emailVerified: claimVerified,
    identity: {
      email: { value: claimEmail, verified: claimVerified },
      phone: null,
      anonymous: false,
    },
    name: null,
    image: null,
    ...overrides,
  }
}

/** In-memory port implementation: proves the port is implementable. */
class FakeUserRepository implements UserRepository {
  private readonly users = new Map<string, UserRecord>()
  private nextId = 1

  findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError> {
    return okAsync(this.users.get(id) ?? null)
  }

  findByEmail(email: Email): ResultAsync<UserRecord | null, RepositoryError> {
    for (const user of this.users.values()) {
      if (user.email === email) {
        return okAsync(user)
      }
    }
    return okAsync(null)
  }

  findByProviderIdentity(
    ref: ProviderIdentityRef
  ): ResultAsync<UserRecord | null, RepositoryError> {
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
    for (const user of this.users.values()) {
      if (user.email === input.email) {
        return errAsync(new UserExistsError(input.email))
      }
    }
    const now = systemClock().now()
    const user: UserRecord = {
      id: defineUserId(`user-${this.nextId}`),
      email: input.email,
      roles: [...input.roles],
      identities:
        input.identity === undefined
          ? []
          : [
              {
                providerId: input.identity.providerId,
                providerUserId: input.identity.providerUserId,
                email: input.email,
                linkedAt: now,
              },
            ],
      createdAt: now,
      updatedAt: now,
    }
    this.users.set(user.id, user)
    this.nextId += 1
    return okAsync(user)
  }

  linkIdentity(userId: UserId, ref: ProviderIdentityRef): ResultAsync<UserRecord, RepositoryError> {
    const user = this.users.get(userId)
    if (!user) {
      return errAsync(new RepositoryError(`linkIdentity: missing user ${userId}`))
    }
    const updated: UserRecord = {
      ...user,
      identities: [
        ...user.identities,
        {
          providerId: ref.providerId,
          providerUserId: ref.providerUserId,
          email: user.email,
          linkedAt: systemClock().now(),
        },
      ],
    }
    this.users.set(userId, updated)
    return okAsync(updated)
  }

  unlinkIdentity(
    userId: UserId,
    ref: ProviderIdentityRef
  ): ResultAsync<UserRecord, RepositoryError> {
    const user = this.users.get(userId)
    if (!user) {
      return errAsync(new RepositoryError(`unlinkIdentity: missing user ${userId}`))
    }
    const updated: UserRecord = {
      ...user,
      identities: user.identities.filter(
        (identity) =>
          identity.providerId !== ref.providerId || identity.providerUserId !== ref.providerUserId
      ),
    }
    this.users.set(userId, updated)
    return okAsync(updated)
  }

  setRoles(userId: UserId, roles: readonly Role[]): ResultAsync<UserRecord, RepositoryError> {
    const user = this.users.get(userId)
    if (!user) {
      return errAsync(new RepositoryError(`setRoles: missing user ${userId}`))
    }
    const updated: UserRecord = { ...user, roles: [...roles] }
    this.users.set(userId, updated)
    return okAsync(updated)
  }

  setEmail(
    userId: UserId,
    email: Email
  ): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
    const user = this.users.get(userId)
    if (!user) {
      return errAsync(new RepositoryError(`setEmail: missing user ${userId}`))
    }
    if (user.email === email) {
      return okAsync(user)
    }
    for (const other of this.users.values()) {
      if (other.id !== userId && other.email === email) {
        return errAsync(new UserExistsError(email))
      }
    }
    const updated: UserRecord = { ...user, email }
    this.users.set(userId, updated)
    return okAsync(updated)
  }
}

/** Fake with `findByPhone` (CAP-9-style repository) for the opt-in branch. */
class PhoneFakeUserRepository extends FakeUserRepository {
  readonly phoneOwners = new Map<string, Email>()

  findByPhone(phoneNumber: PhoneNumber): ResultAsync<UserRecord | null, RepositoryError> {
    const owner = this.phoneOwners.get(phoneNumber)
    return owner === undefined ? okAsync(null) : this.findByEmail(owner)
  }
}

const providerId = defineProviderId('better-auth')

describe('ensureLinkedUser', () => {
  it('creates a user with default roles for an unknown email', async () => {
    const users = new FakeUserRepository()
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      { providerId, profile: profile({ providerUserId: 'ba-1' }), defaultRoles: [role('user')] }
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.email).toBe('user@example.com')
      expect(result.value.roles).toEqual(['user'])
      expect(result.value.identities).toHaveLength(1)
      expect(result.value.identities[0]?.providerUserId).toBe('ba-1')
    }
  })

  it('returns the already-linked user without changes (idempotent)', async () => {
    const users = new FakeUserRepository()
    const deps = { users, logger: nullLogger() }
    const input = {
      providerId,
      profile: profile({ providerUserId: 'ba-1' }),
      defaultRoles: [role('user')],
    }
    const first = await ensureLinkedUser(deps, input)
    expect(first.isOk()).toBe(true)
    const second = await ensureLinkedUser(deps, input)
    expect(second.isOk()).toBe(true)
    if (first.isOk() && second.isOk()) {
      expect(second.value.id).toBe(first.value.id)
      expect(second.value.identities).toHaveLength(1)
    }
  })

  it('links a verified identity to an existing user by email', async () => {
    const users = new FakeUserRepository()
    await users.create({ email: email('user@example.com'), roles: [role('admin')] })
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: profile({ providerUserId: 'ba-9', emailVerified: true }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.roles).toEqual(['admin'])
      expect(result.value.identities).toHaveLength(1)
      expect(result.value.identities[0]?.providerUserId).toBe('ba-9')
    }
  })

  it('syncs the email when the provider reports a new verified address', async () => {
    const users = new FakeUserRepository()
    const deps = { users, logger: nullLogger() }
    const first = await ensureLinkedUser(deps, {
      providerId,
      profile: profile({ providerUserId: 'ba-1' }),
      defaultRoles: [role('user')],
    })
    expect(first.isOk()).toBe(true)
    const second = await ensureLinkedUser(deps, {
      providerId,
      profile: profile({
        providerUserId: 'ba-1',
        email: email('new@example.com'),
        emailVerified: true,
      }),
      defaultRoles: [role('user')],
    })
    expect(second.isOk()).toBe(true)
    if (first.isOk() && second.isOk()) {
      expect(second.value.id).toBe(first.value.id)
      expect(second.value.email).toBe('new@example.com')
    }
  })

  it('keeps a stale email when the new provider address is unverified', async () => {
    const users = new FakeUserRepository()
    const deps = { users, logger: nullLogger() }
    await ensureLinkedUser(deps, {
      providerId,
      profile: profile({ providerUserId: 'ba-1' }),
      defaultRoles: [role('user')],
    })
    const result = await ensureLinkedUser(deps, {
      providerId,
      profile: profile({
        providerUserId: 'ba-1',
        email: email('new@example.com'),
        emailVerified: false,
      }),
      defaultRoles: [role('user')],
    })
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.email).toBe('user@example.com')
    }
  })

  it('refuses to link an unverified identity to an existing user', async () => {
    const users = new FakeUserRepository()
    await users.create({ email: email('user@example.com'), roles: [role('admin')] })
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: profile({ providerUserId: 'ba-evil', emailVerified: false }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedEmailError)
    }
    const untouched = await users.findByEmail(email('user@example.com'))
    expect(untouched.isOk() && untouched.value?.identities).toHaveLength(0)
  })

  it('refuses to provision a user from an unverified identity', async () => {
    const users = new FakeUserRepository()
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: profile({ providerUserId: 'ba-new', emailVerified: false }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedEmailError)
    }
    const missing = await users.findByEmail(email('user@example.com'))
    expect(missing.isOk() && missing.value).toBeNull()
  })

  it('reads the identity.email claim, not the deprecated aliases (PORT-1)', async () => {
    const users = new FakeUserRepository()
    await users.create({ email: email('user@example.com'), roles: [role('admin')] })
    // Alias claims verified; the identity claim says unverified. The
    // claim wins, so linking must refuse exactly as V1 did.
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: profile({
          providerUserId: 'ba-alias',
          emailVerified: true,
          identity: {
            email: { value: email('user@example.com'), verified: false },
            phone: null,
            anonymous: false,
          },
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedEmailError)
    }
  })

  it('refuses a verified phone-only identity without the opt-in policy (PORT-3)', async () => {
    const users = new PhoneFakeUserRepository()
    await users.create({ email: email('owner@example.com'), roles: [role('admin')] })
    users.phoneOwners.set('+14155550132', email('owner@example.com'))
    for (const linkingPolicy of [undefined, { kind: 'verified-email' } as const]) {
      const result = await ensureLinkedUser(
        { users, logger: nullLogger() },
        {
          providerId,
          profile: phoneOnlyProfile('ba-phone'),
          defaultRoles: [role('user')],
          ...(linkingPolicy === undefined ? {} : { linkingPolicy }),
        }
      )
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(UnverifiedIdentityError)
      }
    }
    const untouched = await users.findByEmail(email('owner@example.com'))
    expect(untouched.isOk() && untouched.value?.identities).toHaveLength(0)
  })

  it('links a verified phone-only identity to an existing user when opted in (PORT-3)', async () => {
    const users = new PhoneFakeUserRepository()
    await users.create({ email: email('owner@example.com'), roles: [role('admin')] })
    users.phoneOwners.set('+14155550132', email('owner@example.com'))
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: phoneOnlyProfile('ba-phone'),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.email).toBe('owner@example.com')
      expect(result.value.roles).toEqual(['admin'])
      expect(result.value.identities).toHaveLength(1)
      expect(result.value.identities[0]?.providerUserId).toBe('ba-phone')
    }
  })

  it('never provisions from a verified phone with no existing user (PORT-3)', async () => {
    const users = new PhoneFakeUserRepository()
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: phoneOnlyProfile('ba-phone'),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedIdentityError)
    }
  })

  it('refuses an unverified phone claim even when opted in (PORT-3)', async () => {
    const users = new PhoneFakeUserRepository()
    await users.create({ email: email('owner@example.com'), roles: [role('admin')] })
    users.phoneOwners.set('+14155550132', email('owner@example.com'))
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: phoneOnlyProfile('ba-phone', { verified: false }),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedIdentityError)
    }
    const untouched = await users.findByEmail(email('owner@example.com'))
    expect(untouched.isOk() && untouched.value?.identities).toHaveLength(0)
  })

  it('refuses phone linking when the repository has no findByPhone (PORT-3)', async () => {
    const users = new FakeUserRepository()
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: phoneOnlyProfile('ba-phone'),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedIdentityError)
    }
  })

  it('never links an anonymous identity, even with a verified email or phone (PORT-3/D3)', async () => {
    const users = new PhoneFakeUserRepository()
    await users.create({ email: email('user@example.com'), roles: [role('admin')] })
    users.phoneOwners.set('+14155550132', email('user@example.com'))
    const byEmail = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: profile({
          providerUserId: 'ba-anon',
          identity: {
            email: { value: email('user@example.com'), verified: true },
            phone: null,
            anonymous: true,
          },
        }),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(byEmail.isErr()).toBe(true)
    if (byEmail.isErr()) {
      expect(byEmail.error).toBeInstanceOf(UnverifiedIdentityError)
    }
    const byPhone = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: phoneOnlyProfile('ba-anon', { anonymous: true }),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(byPhone.isErr()).toBe(true)
    const untouched = await users.findByEmail(email('user@example.com'))
    expect(untouched.isOk() && untouched.value?.identities).toHaveLength(0)
  })

  it('refuses a session with no email claim (PORT-1)', async () => {
    const users = new FakeUserRepository()
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: profile({
          providerUserId: 'ba-no-email',
          identity: { email: null, phone: null, anonymous: true },
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnverifiedIdentityError)
    }
  })
})

/** Phone-capable fake that also syncs (`setPhone`), optionally failing. */
class PhoneSyncFakeUserRepository extends PhoneFakeUserRepository {
  readonly setPhoneCalls: { userId: UserId; phone: PhoneNumber }[] = []
  failSetPhone = false

  setPhone(userId: UserId, phoneNumber: PhoneNumber): ResultAsync<UserRecord, RepositoryError> {
    this.setPhoneCalls.push({ userId, phone: phoneNumber })
    if (this.failSetPhone) {
      return errAsync(new RepositoryError('setPhone: storage down'))
    }
    return this.findById(userId).andThen((user) =>
      user === null
        ? errAsync(new RepositoryError(`setPhone: missing user ${userId}`))
        : okAsync({ ...user, phone: phoneNumber })
    )
  }
}

type LogLine = { readonly level: 'info' | 'warn'; readonly message: string }

function recordingLogger(lines: LogLine[]): LoggerPort {
  const logger: LoggerPort = {
    ...nullLogger(),
    info: (message) => {
      lines.push({ level: 'info', message })
    },
    warn: (message) => {
      lines.push({ level: 'warn', message })
    },
    child: () => logger,
  }
  return logger
}

function emailAndPhoneProfile(
  providerUserId: string,
  claims: { email: string; emailVerified: boolean; phoneVerified: boolean }
): ProviderProfile {
  return profile({
    providerUserId,
    identity: {
      email: { value: email(claims.email), verified: claims.emailVerified },
      phone: { value: phone('+14155550132'), verified: claims.phoneVerified },
      anonymous: false,
    },
  })
}

describe('ensureLinkedUser phone handling (CAP-9, issue #110)', () => {
  it('syncs a verified phone claim onto an already-linked user', async () => {
    const users = new PhoneSyncFakeUserRepository()
    const ref = { providerId, providerUserId: 'ba-sync' }
    await users.create({ email: email('sync@example.com'), roles: [role('user')], identity: ref })
    const lines: LogLine[] = []
    const result = await ensureLinkedUser(
      { users, logger: recordingLogger(lines) },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-sync', {
          email: 'sync@example.com',
          emailVerified: true,
          phoneVerified: true,
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isOk() && result.value.phone).toBe('+14155550132')
    expect(users.setPhoneCalls).toHaveLength(1)
    expect(lines).toContainEqual({ level: 'info', message: 'phone synced from provider' })
  })

  it('never syncs an UNVERIFIED phone claim', async () => {
    const users = new PhoneSyncFakeUserRepository()
    const ref = { providerId, providerUserId: 'ba-unverified-phone' }
    await users.create({ email: email('up@example.com'), roles: [role('user')], identity: ref })
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-unverified-phone', {
          email: 'up@example.com',
          emailVerified: true,
          phoneVerified: false,
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isOk()).toBe(true)
    expect(users.setPhoneCalls).toEqual([])
  })

  it('a failed phone sync is logged and keeps the valid link', async () => {
    const users = new PhoneSyncFakeUserRepository()
    users.failSetPhone = true
    const ref = { providerId, providerUserId: 'ba-sync-fail' }
    await users.create({ email: email('fail@example.com'), roles: [role('user')], identity: ref })
    const lines: LogLine[] = []
    const result = await ensureLinkedUser(
      { users, logger: recordingLogger(lines) },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-sync-fail', {
          email: 'fail@example.com',
          emailVerified: true,
          phoneVerified: true,
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isOk() && result.value.email).toBe('fail@example.com')
    expect(lines).toContainEqual({
      level: 'warn',
      message: 'phone sync failed; keeping linked user',
    })
  })

  it('a repository without setPhone links without syncing', async () => {
    const users = new PhoneFakeUserRepository()
    const ref = { providerId, providerUserId: 'ba-no-setphone' }
    await users.create({ email: email('nos@example.com'), roles: [role('user')], identity: ref })
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-no-setphone', {
          email: 'nos@example.com',
          emailVerified: true,
          phoneVerified: true,
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isOk()).toBe(true)
    expect(result.isOk() && result.value.phone).toBeUndefined()
  })

  it('an already-linked phone-only identity returns its user without email or phone writes', async () => {
    const users = new PhoneSyncFakeUserRepository()
    const ref = { providerId, providerUserId: 'ba-linked-phone' }
    await users.create({ email: email('lp@example.com'), roles: [role('user')], identity: ref })
    // The fast path holds under the DEFAULT policy too: the link
    // already exists, so no email claim is needed to resolve it.
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      { providerId, profile: phoneOnlyProfile('ba-linked-phone'), defaultRoles: [role('user')] }
    )
    expect(result.isOk() && result.value.email).toBe('lp@example.com')
    expect(users.setPhoneCalls).toEqual([])
  })

  it('an unverified placeholder email links by VERIFIED phone only under the opt-in policy', async () => {
    const users = new PhoneSyncFakeUserRepository()
    await users.create({ email: email('owner@example.com'), roles: [role('admin')] })
    users.phoneOwners.set('+14155550132', email('owner@example.com'))
    const placeholder = {
      email: 'temp-123@phone.invalid',
      emailVerified: false,
      phoneVerified: true,
    }
    const optIn = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-placeholder', placeholder),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(optIn.isOk() && optIn.value.email).toBe('owner@example.com')
    expect(optIn.isOk() && optIn.value.identities.map((i) => i.providerUserId)).toEqual([
      'ba-placeholder',
    ])

    // Default policy: the unverified email refuses; the phone is ignored.
    const byDefault = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-placeholder-default', placeholder),
        defaultRoles: [role('user')],
      }
    )
    expect(byDefault.isErr() && byDefault.error).toBeInstanceOf(UnverifiedEmailError)

    // Opt-in with an UNVERIFIED phone: still refused, never provisioned.
    const unverifiedPhone = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-placeholder-unverified', {
          ...placeholder,
          phoneVerified: false,
        }),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(unverifiedPhone.isErr() && unverifiedPhone.error).toBeInstanceOf(UnverifiedEmailError)
    const provisioned = await users.findByEmail(email('temp-123@phone.invalid'))
    expect(provisioned.isOk() && provisioned.value).toBeNull()
  })

  it('an unverified email held by an existing user refuses even with a verified phone', async () => {
    const users = new PhoneSyncFakeUserRepository()
    await users.create({ email: email('held@example.com'), roles: [role('admin')] })
    users.phoneOwners.set('+14155550132', email('held@example.com'))
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-held', {
          email: 'held@example.com',
          emailVerified: false,
          phoneVerified: true,
        }),
        defaultRoles: [role('user')],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      }
    )
    expect(result.isErr() && result.error).toBeInstanceOf(UnverifiedEmailError)
    const held = await users.findByEmail(email('held@example.com'))
    expect(held.isOk() && held.value?.identities).toHaveLength(0)
  })

  it('a provisioned user carries the verified phone claim', async () => {
    const users = new PhoneSyncFakeUserRepository()
    const captured: NewUser[] = []
    const original = users.create.bind(users)
    users.create = (input: NewUser) => {
      captured.push(input)
      return original(input)
    }
    const result = await ensureLinkedUser(
      { users, logger: nullLogger() },
      {
        providerId,
        profile: emailAndPhoneProfile('ba-new-phone', {
          email: 'new@example.com',
          emailVerified: true,
          phoneVerified: true,
        }),
        defaultRoles: [role('user')],
      }
    )
    expect(result.isOk()).toBe(true)
    expect(captured[0]?.phone).toBe('+14155550132')
  })

  it('an unknown linking policy kind fails loudly, never as a silent no-op', async () => {
    const users = new FakeUserRepository()
    await expect(
      ensureLinkedUser(
        { users, logger: nullLogger() },
        {
          providerId,
          profile: phoneOnlyProfile('ba-bogus-policy'),
          defaultRoles: [role('user')],
          linkingPolicy: { kind: 'bogus' } as never,
        }
      )
    ).rejects.toThrow(/Unreachable/)
  })
})
