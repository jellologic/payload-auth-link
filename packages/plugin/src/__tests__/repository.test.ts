import {
  defineProviderId,
  defineUserId,
  parseEmail,
  parseRole,
  RepositoryError,
  UserExistsError,
  type Email,
  type UserRepository,
} from '@payload-auth-link/core'
import { ValidationError, type Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { wireOptions } from '../options.js'
import { createPayloadUserRepository } from '../repository.js'
import { createStubProvider } from './stub-provider.js'

function email(raw: string): Email {
  const parsed = parseEmail(raw)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

const userId = defineUserId('user-1')
const ref = { providerId: defineProviderId('stub'), providerUserId: 'stub-1' }

const doc = {
  id: 'user-1',
  email: 'linked@test.dev',
  roles: ['user'],
  identities: [] as unknown[],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
}

const linkedDoc = {
  ...doc,
  identities: [
    {
      providerId: 'stub',
      providerUserId: 'stub-1',
      email: 'linked@test.dev',
      linkedAt: new Date().toISOString(),
    },
  ],
}

type PayloadStub = {
  find?: (args: unknown) => Promise<unknown>
  findByID?: (args: unknown) => Promise<unknown>
  create?: (args: unknown) => Promise<unknown>
  update?: (args: unknown) => Promise<unknown>
}

function repository(stub: PayloadStub): UserRepository {
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    secret: 'unit-test-secret-32-chars-minimum!!',
    roles: ['user', 'admin'],
    defaultRole: 'user',
    providers: [createStubProvider().provider],
  })
  const rejecting = () => Promise.reject(new Error('unexpected call'))
  return createPayloadUserRepository({
    payload: {
      find: stub.find ?? rejecting,
      findByID: stub.findByID ?? rejecting,
      create: stub.create ?? rejecting,
      update: stub.update ?? rejecting,
    } as unknown as Payload,
    map: wired.config.map,
    defaultRole: wired.config.defaultRole,
    logger: wired.logger,
    clock: wired.clock,
    ids: wired.ids,
    depth: wired.depth,
  })
}

const found = (docs: unknown[]) => () => Promise.resolve({ docs })
const uniqueEmailViolation = () =>
  Promise.reject(
    new ValidationError({ errors: [{ path: 'email', message: 'Value must be unique' }] })
  )
const outage = new Error('db down')
const down = () => Promise.reject(outage)

function expectRepositoryError(result: { isErr(): boolean; error?: unknown }): void {
  expect(result.isErr()).toBe(true)
  expect(result.error).toBeInstanceOf(RepositoryError)
}

describe('payload user repository reads', () => {
  it('maps findById, findByEmail, and findByProviderIdentity results', async () => {
    const find = vi.fn(found([linkedDoc]))
    const users = repository({ find, findByID: () => Promise.resolve(doc) })
    expect((await users.findById(userId))._unsafeUnwrap()?.id).toBe('user-1')
    expect((await users.findByEmail(email('linked@test.dev')))._unsafeUnwrap()?.id).toBe('user-1')
    expect((await users.findByProviderIdentity(ref))._unsafeUnwrap()?.identities).toHaveLength(1)
    expect(find).toHaveBeenLastCalledWith(
      expect.objectContaining({ limit: 1, overrideAccess: true, pagination: false })
    )
  })

  it('wraps read outages as RepositoryError with their cause', async () => {
    const users = repository({ find: down, findByID: down })
    const byId = await users.findById(userId)
    expectRepositoryError(byId)
    expect(byId._unsafeUnwrapErr().cause).toBe(outage)
    expectRepositoryError(await users.findByEmail(email('linked@test.dev')))
  })
})

describe('payload user repository create', () => {
  const input = {
    email: email('linked@test.dev'),
    roles: [parseRole('user')._unsafeUnwrap()],
    identity: ref,
  }

  it('maps the created document', async () => {
    const users = repository({ create: () => Promise.resolve(linkedDoc) })
    const created = await users.create(input)
    expect(created._unsafeUnwrap().id).toBe('user-1')
  })

  it('maps unique email violations to UserExistsError', async () => {
    const users = repository({ create: uniqueEmailViolation })
    expect((await users.create(input))._unsafeUnwrapErr()).toBeInstanceOf(UserExistsError)
  })

  it('maps other failures and unmappable results to RepositoryError', async () => {
    expectRepositoryError(await repository({ create: down }).create(input))
    const otherValidation = () =>
      Promise.reject(new ValidationError({ errors: [{ path: 'roles', message: 'required' }] }))
    expectRepositoryError(await repository({ create: otherValidation }).create(input))
    expectRepositoryError(
      await repository({ create: () => Promise.resolve({ id: 1 }) }).create(input)
    )
  })
})

describe('payload user repository linkIdentity', () => {
  it('fails when the user is missing', async () => {
    expectRepositoryError(await repository({ find: found([]) }).linkIdentity(userId, ref))
  })

  it('returns the existing record without writing when already linked', async () => {
    const update = vi.fn(down)
    const users = repository({ find: found([linkedDoc]), update })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    expect(update).not.toHaveBeenCalled()
  })

  it('appends the identity, keeping existing rows', async () => {
    const update = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(linkedDoc))
    const other = { ...linkedDoc, identities: [{ ...linkedDoc.identities[0], providerId: 'x' }] }
    const users = repository({ find: found([other]), update })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    expect(update.mock.calls[0]?.[0]).toMatchObject({
      id: userId,
      data: { identities: [{ providerId: 'x' }, { providerId: 'stub', providerUserId: 'stub-1' }] },
    })
  })

  it('maps write outages and unmappable results to RepositoryError', async () => {
    expectRepositoryError(
      await repository({ find: found([doc]), update: down }).linkIdentity(userId, ref)
    )
    expectRepositoryError(
      await repository({ find: found([doc]), update: () => Promise.resolve(null) }).linkIdentity(
        userId,
        ref
      )
    )
  })
})

describe('payload user repository setEmail', () => {
  const next = email('next@test.dev')

  it('fails when the user is missing', async () => {
    expectRepositoryError(await repository({ find: found([]) }).setEmail(userId, next))
  })

  it('skips the write when the email is unchanged', async () => {
    const update = vi.fn(down)
    const users = repository({ find: found([doc]), update })
    expect((await users.setEmail(userId, email('linked@test.dev'))).isOk()).toBe(true)
    expect(update).not.toHaveBeenCalled()
  })

  it('writes a changed email', async () => {
    const users = repository({
      find: found([doc]),
      update: () => Promise.resolve({ ...doc, email: 'next@test.dev' }),
    })
    expect((await users.setEmail(userId, next))._unsafeUnwrap().email).toBe('next@test.dev')
  })

  it('maps unique violations, outages, and unmappable results', async () => {
    const taken = await repository({ find: found([doc]), update: uniqueEmailViolation }).setEmail(
      userId,
      next
    )
    expect(taken._unsafeUnwrapErr()).toBeInstanceOf(UserExistsError)
    expectRepositoryError(
      await repository({ find: found([doc]), update: down }).setEmail(userId, next)
    )
    expectRepositoryError(
      await repository({ find: found([doc]), update: () => Promise.resolve(null) }).setEmail(
        userId,
        next
      )
    )
  })
})

describe('payload user repository setRoles', () => {
  const roles = [parseRole('admin')._unsafeUnwrap()]

  it('writes the roles and maps the result', async () => {
    const users = repository({ update: () => Promise.resolve({ ...doc, roles: ['admin'] }) })
    expect((await users.setRoles(userId, roles))._unsafeUnwrap().roles).toEqual(['admin'])
  })

  it('maps outages and unmappable results to RepositoryError', async () => {
    expectRepositoryError(await repository({ update: down }).setRoles(userId, roles))
    expectRepositoryError(
      await repository({ update: () => Promise.resolve(null) }).setRoles(userId, roles)
    )
  })
})
