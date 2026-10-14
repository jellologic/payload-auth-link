import {
  defineProviderId,
  defineUserId,
  parseEmail,
  parsePhoneNumber,
  parseRole,
  RepositoryError,
  UserExistsError,
  type Email,
  type UserRepository,
  nullLogger,
  type LoggerPort,
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
  linkable: true,
  linkableEmail: 'linked@test.dev',
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

function repository(stub: PayloadStub, logger?: LoggerPort): UserRepository {
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['user', 'admin'],
    defaultRole: 'user',
    providers: [createStubProvider().provider],
  })
  const rejecting = () => Promise.reject(new Error('unexpected call'))
  return createPayloadUserRepository({
    payload: {
      find: stub.find ?? rejecting,
      findByID: stub.findByID ?? (() => Promise.resolve({})),
      create: stub.create ?? rejecting,
      update: stub.update ?? rejecting,
    } as unknown as Payload,
    map: wired.config.map,
    defaultRole: wired.config.defaultRole,
    logger: logger ?? wired.logger,
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

describe('findByEmail linkability gate (GHSA-98hq-hh6v-2p2r)', () => {
  it('returns unproven documents as null, with a logged reason', async () => {
    const unproven = { ...doc, linkable: false }
    const { logger, warn } = (() => {
      const warnings: string[] = []
      const base = nullLogger()
      const l: LoggerPort = {
        ...base,
        warn: (message) => warnings.push(message),
        child: () => l,
      }
      return { logger: l, warn: warnings }
    })()
    const users = repository(
      { find: found([unproven]), findByID: () => Promise.resolve({}) },
      logger
    )
    expect((await users.findByEmail(email('linked@test.dev')))._unsafeUnwrap()).toBeNull()
    expect(warn.some((message) => message.includes('not marked linkable'))).toBe(true)
  })

  it('refuses when the linkable proof does not match the document email', async () => {
    const moved = {
      ...doc,
      linkable: true,
      linkableEmail: 'linked@test.dev',
      email: 'moved@test.dev',
    }
    const { logger, warn } = (() => {
      const warnings: string[] = []
      const base = nullLogger()
      const l: LoggerPort = {
        ...base,
        warn: (message) => warnings.push(message),
        child: () => l,
      }
      return { logger: l, warn: warnings }
    })()
    const users = repository({ find: found([moved]), findByID: () => Promise.resolve({}) }, logger)
    expect((await users.findByEmail(email('moved@test.dev')))._unsafeUnwrap()).toBeNull()
    expect(warn.some((message) => message.includes('does not match the document email'))).toBe(true)
  })

  it('keeps the proof bound after a provider-email resync (setEmail moves linkableEmail)', async () => {
    let written: { data?: Record<string, unknown> } | undefined
    const users = repository({
      find: found([linkedDoc]),
      update: (args: unknown) => {
        written = args as { data?: Record<string, unknown> }
        return Promise.resolve({ ...linkedDoc, email: 'next@test.dev' })
      },
    })
    const resynced = await users.setEmail(userId, email('next@test.dev'))
    expect(resynced.isOk()).toBe(true)
    expect(written?.data?.linkable).toBe(true)
    expect(written?.data?.linkableEmail).toBe('next@test.dev')
  })

  it('refuses linkable documents whose proof was never granted (missing linkableEmail)', async () => {
    const unproven = { ...doc, linkable: true, linkableEmail: undefined }
    const { logger, warn } = (() => {
      const warnings: string[] = []
      const base = nullLogger()
      const l: LoggerPort = {
        ...base,
        warn: (message) => warnings.push(message),
        child: () => l,
      }
      return { logger: l, warn: warnings }
    })()
    const users = repository(
      { find: found([unproven]), findByID: () => Promise.resolve({}) },
      logger
    )
    expect((await users.findByEmail(email('linked@test.dev')))._unsafeUnwrap()).toBeNull()
    expect(warn.some((message) => message.includes('does not match the document email'))).toBe(true)
  })

  it('linkIdentity still links when the best-effort password probe fails', async () => {
    const update = vi.fn<(args: unknown) => Promise<unknown>>(() =>
      Promise.resolve({
        ...linkedDoc,
        identities: [
          ...linkedDoc.identities,
          { ...linkedDoc.identities[0], providerUserId: 'stub-2' },
        ],
      })
    )
    const users = repository({
      find: found([linkedDoc]),
      findByID: () => Promise.reject(new Error('db down')),
      update,
    })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
  })

  it('returns documents Payload itself verified', async () => {
    const verified = { ...doc, linkable: false, _verified: true }
    const users = repository({
      find: found([verified]),
      findByID: () => Promise.resolve({}),
    })
    expect((await users.findByEmail(email('linked@test.dev')))._unsafeUnwrap()?.id).toBe('user-1')
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

  it('rewrites linked-identity rows carrying the old address (issue #21)', async () => {
    let written: { data?: Record<string, unknown> } | undefined
    const users = repository({
      find: found([linkedDoc]),
      update: (args: unknown) => {
        written = args as { data?: Record<string, unknown> }
        return Promise.resolve({ ...linkedDoc, email: 'next@test.dev' })
      },
    })
    expect((await users.setEmail(userId, next))._unsafeUnwrap().email).toBe('next@test.dev')
    const identities = written?.data?.identities as Array<Record<string, unknown>>
    expect(identities).toHaveLength(1)
    // The row claimed the old address; the write re-asserts the same
    // identity at the new one.
    expect(identities[0]?.email).toBe('next@test.dev')
    expect(identities[0]?.providerUserId).toBe('stub-1')
    // Unrelated identity rows (different address) stay untouched.
    const mixedDoc = {
      ...linkedDoc,
      identities: [
        ...linkedDoc.identities,
        {
          providerId: 'stub',
          providerUserId: 'stub-2',
          email: 'other@test.dev',
          linkedAt: new Date().toISOString(),
        },
      ],
    }
    let second: { data?: Record<string, unknown> } | undefined
    await repository({
      find: found([mixedDoc]),
      update: (args: unknown) => {
        second = args as { data?: Record<string, unknown> }
        return Promise.resolve({ ...mixedDoc, email: 'next@test.dev' })
      },
    }).setEmail(userId, next)
    const secondIdentities = second?.data?.identities as Array<Record<string, unknown>>
    expect(secondIdentities[0]?.email).toBe('next@test.dev')
    expect(secondIdentities[1]?.email).toBe('other@test.dev')
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

describe('payload user repository unlinkIdentity (CAP-14)', () => {
  it('fails when the user is missing', async () => {
    expectRepositoryError(await repository({ find: found([]) }).unlinkIdentity(userId, ref))
  })

  it('is an idempotent no-op when the identity is not linked', async () => {
    const update = vi.fn(down)
    const users = repository({ find: found([doc]), update })
    expect((await users.unlinkIdentity(userId, ref)).isOk()).toBe(true)
    expect(update).not.toHaveBeenCalled()
  })

  it('removes only the matching row and never deletes the user', async () => {
    const update = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(doc))
    const users = repository({ find: found([linkedDoc]), update })
    const result = await users.unlinkIdentity(userId, ref)
    expect(result._unsafeUnwrap().identities).toEqual([])
    expect(update.mock.calls[0]?.[0]).toMatchObject({ id: userId, data: { identities: [] } })
  })

  it('maps write outages and unmappable results to RepositoryError', async () => {
    expectRepositoryError(
      await repository({ find: found([linkedDoc]), update: down }).unlinkIdentity(userId, ref)
    )
    expectRepositoryError(
      await repository({
        find: found([linkedDoc]),
        update: () => Promise.resolve(null),
      }).unlinkIdentity(userId, ref)
    )
  })
})

describe('payload user repository phone (CAP-9)', () => {
  const phone = parsePhoneNumber('+14155550132')._unsafeUnwrap()
  const phoneDoc = { ...doc, phone: '+14155550132' }

  it('finds a user by stored E.164 phone', async () => {
    const find = vi.fn(found([phoneDoc]))
    const users = repository({ find })
    expect((await users.findByPhone?.(phone))?._unsafeUnwrap()?.phone).toBe('+14155550132')
    expect(find).toHaveBeenLastCalledWith(
      expect.objectContaining({ where: { phone: { equals: '+14155550132' } } })
    )
    expectRepositoryError(
      (await repository({ find: down }).findByPhone?.(phone)) ?? { isErr: () => false }
    )
  })

  it('setPhone fails when the user is missing and no-ops when unchanged', async () => {
    expectRepositoryError(
      (await repository({ find: found([]) }).setPhone?.(userId, phone)) ?? { isErr: () => false }
    )
    const update = vi.fn(down)
    const users = repository({ find: found([phoneDoc]), update })
    expect((await users.setPhone?.(userId, phone))?.isOk()).toBe(true)
    expect(update).not.toHaveBeenCalled()
  })

  it('setPhone refuses to steal a number held by another user', async () => {
    const other = { ...phoneDoc, id: 'user-2' }
    let call = 0
    const find = () => {
      call += 1
      return Promise.resolve({ docs: [call === 1 ? doc : other] })
    }
    const result = await repository({ find }).setPhone?.(userId, phone)
    expectRepositoryError(result ?? { isErr: () => false })
  })

  it('setPhone writes a new number and maps failures', async () => {
    let call = 0
    const find = () => {
      call += 1
      return Promise.resolve({ docs: call === 1 ? [doc] : [] })
    }
    const users = repository({ find, update: () => Promise.resolve(phoneDoc) })
    expect((await users.setPhone?.(userId, phone))?._unsafeUnwrap().phone).toBe('+14155550132')
    let failingCall = 0
    const failingFind = () => {
      failingCall += 1
      return Promise.resolve({ docs: failingCall === 1 ? [doc] : [] })
    }
    expectRepositoryError(
      (await repository({ find: failingFind, update: down }).setPhone?.(userId, phone)) ?? {
        isErr: () => false,
      }
    )
    let nullCall = 0
    const nullFind = () => {
      nullCall += 1
      return Promise.resolve({ docs: nullCall === 1 ? [doc] : [] })
    }
    expectRepositoryError(
      (await repository({ find: nullFind, update: () => Promise.resolve(null) }).setPhone?.(
        userId,
        phone
      )) ?? { isErr: () => false }
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
