import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import { describe, expect, it } from 'vitest'
import { nullLogger, systemClock } from '../defaults.js'
import { parseEmail, type Email } from '../email.js'
import { RepositoryError, UnverifiedEmailError, UserExistsError } from '../errors.js'
import {
  defineProviderId,
  defineUserId,
  type NewUser,
  type ProviderIdentityRef,
  type ProviderProfile,
  type UserId,
  type UserRecord,
  type UserRepository,
} from '../ports.js'
import { parseRole, type Role } from '../roles.js'
import { ensureLinkedUser } from '../use-cases/ensure-linked-user.js'

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
  return {
    email: email('user@example.com'),
    emailVerified: true,
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
})
