import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import { describe, expect, it } from 'vitest'
import { parseEmail } from '../email.js'
import { RepositoryError, UserExistsError } from '../errors.js'
import type { IdentityEvent } from '../events.js'
import {
  defineProviderId,
  defineUserId,
  nullLogger,
  type Email,
  type NewUser,
  type ProviderIdentityRef,
  type Role,
  type UserId,
  type UserRecord,
  type UserRepository,
} from '../index.js'
import { applyIdentityEvent } from '../use-cases/apply-identity-event.js'

function emailOf(value: string): Email {
  const parsed = parseEmail(value)
  if (parsed.isErr()) throw new Error('test email must parse')
  return parsed.value
}

const providerId = defineProviderId('better-auth')
const ref: ProviderIdentityRef = { providerId, providerUserId: 'ba-1' }

class FakeUsers implements UserRepository {
  readonly users = new Map<UserId, UserRecord>()
  readonly setEmailCalls: Email[] = []

  seed(): UserRecord {
    const now = new Date('2026-01-01T00:00:00.000Z')
    const user: UserRecord = {
      id: defineUserId('1'),
      email: emailOf('old@example.com'),
      roles: [],
      identities: [{ ...ref, email: emailOf('old@example.com'), linkedAt: now }],
      createdAt: now,
      updatedAt: now,
    }
    this.users.set(user.id, user)
    return user
  }

  findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError> {
    return okAsync(this.users.get(id) ?? null)
  }
  findByEmail(email: Email): ResultAsync<UserRecord | null, RepositoryError> {
    return okAsync([...this.users.values()].find((user) => user.email === email) ?? null)
  }
  findByProviderIdentity(
    candidate: ProviderIdentityRef
  ): ResultAsync<UserRecord | null, RepositoryError> {
    return okAsync(
      [...this.users.values()].find((user) =>
        user.identities.some(
          (identity) =>
            identity.providerId === candidate.providerId &&
            identity.providerUserId === candidate.providerUserId
        )
      ) ?? null
    )
  }
  create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
    return errAsync(new UserExistsError(input.email))
  }
  linkIdentity(userId: UserId): ResultAsync<UserRecord, RepositoryError> {
    return errAsync(new RepositoryError(`linkIdentity: ${userId}`))
  }
  unlinkIdentity(
    userId: UserId,
    target: ProviderIdentityRef
  ): ResultAsync<UserRecord, RepositoryError> {
    const user = this.users.get(userId)
    if (!user) return errAsync(new RepositoryError('missing user'))
    const updated: UserRecord = {
      ...user,
      identities: user.identities.filter(
        (identity) =>
          identity.providerId !== target.providerId ||
          identity.providerUserId !== target.providerUserId
      ),
    }
    this.users.set(userId, updated)
    return okAsync(updated)
  }
  setRoles(userId: UserId, roles: readonly Role[]): ResultAsync<UserRecord, RepositoryError> {
    const user = this.users.get(userId)
    if (!user) return errAsync(new RepositoryError('missing user'))
    const updated = { ...user, roles: [...roles] }
    this.users.set(userId, updated)
    return okAsync(updated)
  }
  setEmail(
    userId: UserId,
    email: Email
  ): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
    this.setEmailCalls.push(email)
    const user = this.users.get(userId)
    if (!user) return errAsync(new RepositoryError('missing user'))
    const updated = { ...user, email }
    this.users.set(userId, updated)
    return okAsync(updated)
  }
}

const base = { providerId, providerUserId: 'ba-1' } as const

describe('applyIdentityEvent (CAP-14)', () => {
  it('syncs a verified email change to the Payload user', async () => {
    const users = new FakeUsers()
    users.seed()
    const event: IdentityEvent = {
      ...base,
      type: 'email-changed',
      email: emailOf('new@example.com'),
      verified: true,
    }
    const result = await applyIdentityEvent(users, event, nullLogger())
    expect(result.isOk()).toBe(true)
    expect(users.users.get(defineUserId('1'))?.email).toBe('new@example.com')
  })

  it('ignores an unverified email change (D9) without touching the repository email', async () => {
    const users = new FakeUsers()
    users.seed()
    const event: IdentityEvent = {
      ...base,
      type: 'email-changed',
      email: emailOf('attacker@example.com'),
      verified: false,
    }
    const result = await applyIdentityEvent(users, event, nullLogger())
    expect(result.isOk()).toBe(true)
    expect(users.setEmailCalls).toEqual([])
    expect(users.users.get(defineUserId('1'))?.email).toBe('old@example.com')
  })

  it('unlinks the identity on user-deleted but keeps the Payload user (D9)', async () => {
    const users = new FakeUsers()
    users.seed()
    const result = await applyIdentityEvent(users, { ...base, type: 'user-deleted' }, nullLogger())
    expect(result.isOk()).toBe(true)
    const user = users.users.get(defineUserId('1'))
    expect(user).toBeDefined()
    expect(user?.identities).toEqual([])
  })

  it('no-ops for a provider user that was never linked', async () => {
    const users = new FakeUsers()
    const result = await applyIdentityEvent(
      users,
      { ...base, type: 'identity-unlinked' },
      nullLogger()
    )
    expect(result.isOk()).toBe(true)
    expect(users.users.size).toBe(0)
  })
})
