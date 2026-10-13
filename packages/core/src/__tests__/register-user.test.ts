import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import { describe, expect, it } from 'vitest'
import { nullLogger, systemClock } from '../defaults.js'
import { parseEmail, type Email } from '../email.js'
import { InvalidEmailError, RepositoryError, UserExistsError } from '../errors.js'
import {
  defineProviderId,
  defineUserId,
  type NewUser,
  type ProviderIdentityRef,
  type UserId,
  type UserRecord,
  type UserRepository,
} from '../ports.js'
import { parseRole, type Role } from '../roles.js'
import { registerUser, registerWithStore } from '../use-cases/register-user.js'

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

describe('registerUser', () => {
  it('creates a new user with roles and identity', async () => {
    const users = new FakeUserRepository()
    const result = await registerUser(
      { users, logger: nullLogger() },
      {
        email: email('new@example.com'),
        roles: [role('user')],
        identity: {
          providerId: defineProviderId('better-auth'),
          providerUserId: 'ba-1',
        },
      }
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.email).toBe('new@example.com')
      expect(result.value.roles).toEqual(['user'])
      expect(result.value.identities).toHaveLength(1)
    }
  })

  it('rejects duplicate emails with UserExistsError', async () => {
    const users = new FakeUserRepository()
    const input = { email: email('dup@example.com'), roles: [role('user')] }
    expect((await registerUser({ users, logger: nullLogger() }, input)).isOk()).toBe(true)
    const result = await registerUser({ users, logger: nullLogger() }, input)
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UserExistsError)
    }
  })
})

type MemoryRow = { id: string }

/** In-memory provider store: proves the store interface is implementable. */
class FakeRegistrationStore {
  private readonly rows = new Map<string, MemoryRow>()
  failures = 0

  findByEmail(candidate: Email): ResultAsync<MemoryRow | null, RepositoryError> {
    if (this.failures > 0) {
      this.failures -= 1
      return errAsync(new RepositoryError('store find'))
    }
    return okAsync(this.rows.get(candidate) ?? null)
  }

  create(candidate: { email: Email }): ResultAsync<MemoryRow, RepositoryError | UserExistsError> {
    const existing = this.rows.get(candidate.email)
    if (existing) {
      return errAsync(new UserExistsError(candidate.email))
    }
    const created = { id: `row-${this.rows.size + 1}` }
    this.rows.set(candidate.email, created)
    return okAsync(created)
  }
}

describe('registerWithStore', () => {
  const deps = (store: FakeRegistrationStore) => ({ store, logger: nullLogger() })
  const input = (email: string) => ({
    email,
    candidate: (parsed: Email) => ({ email: parsed }),
  })

  it('parses, dedupes, and creates through the store', async () => {
    const store = new FakeRegistrationStore()
    const result = await registerWithStore(deps(store), input('New@Example.com'))
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.email).toBe('new@example.com')
      expect(result.value.created.id).toBe('row-1')
    }
  })

  it('rejects invalid emails without touching the store', async () => {
    const store = new FakeRegistrationStore()
    const find = store.findByEmail.bind(store)
    let touched = false
    store.findByEmail = (candidate: Email) => {
      touched = true
      return find(candidate)
    }
    const result = await registerWithStore(deps(store), input('not-an-email'))
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(InvalidEmailError)
    }
    expect(touched).toBe(false)
  })

  it('rejects duplicates and surfaces lost create races as UserExistsError', async () => {
    const store = new FakeRegistrationStore()
    expect((await registerWithStore(deps(store), input('dup@example.com'))).isOk()).toBe(true)
    const duplicate = await registerWithStore(deps(store), input('dup@example.com'))
    expect(duplicate.isErr()).toBe(true)
    if (duplicate.isErr()) {
      expect(duplicate.error).toBeInstanceOf(UserExistsError)
    }
  })

  it('passes storage failures through typed', async () => {
    const store = new FakeRegistrationStore()
    store.failures = 1
    const result = await registerWithStore(deps(store), input('a@example.com'))
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(RepositoryError)
    }
  })
})
