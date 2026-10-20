import {
  authLinkWriteMarker,
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
import { linkableCreateMarker } from '../collections.js'
import { wireOptions } from '../options.js'
import { createPayloadUserRepository, type UserDocumentWrite } from '../repository.js'
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
  /**
   * The database-adapter write the repository scopes identity and
   * credential fields through (issue #144); `update` is the Local API
   * operation and must stay untouched by linkIdentity/unlinkIdentity.
   */
  db?: {
    updateOne?: (args: unknown) => Promise<unknown>
    beginTransaction?: () => Promise<string>
    commitTransaction?: () => Promise<void>
    rollbackTransaction?: () => Promise<void>
  }
}

function repository(
  stub: PayloadStub,
  logger?: LoggerPort,
  onWrite?: (write: UserDocumentWrite) => void
): UserRepository {
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
      db: {
        updateOne: stub.db?.updateOne ?? rejecting,
        beginTransaction: stub.db?.beginTransaction,
        commitTransaction: stub.db?.commitTransaction,
        rollbackTransaction: stub.db?.rollbackTransaction,
      },
    } as unknown as Payload,
    map: wired.config.map,
    defaultRole: wired.config.defaultRole,
    logger: logger ?? wired.logger,
    clock: wired.clock,
    ids: wired.ids,
    depth: wired.depth,
    onWrite,
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

  it('maps a collision thrown by another copy of payload (no shared class) too', async () => {
    // A Payload v4 host with the plugin resolving another `payload`: the
    // error is structurally a ValidationError but not `instanceof` ours.
    const foreign = Object.assign(new Error('The following field is invalid: email'), {
      name: 'ValidationError',
      data: {
        collection: 'users',
        errors: [{ path: 'email', message: 'A user with the given email is already registered.' }],
      },
    })
    const users = repository({ create: () => Promise.reject(foreign) })
    expect((await users.create(input))._unsafeUnwrapErr()).toBeInstanceOf(UserExistsError)
    const unrelated = Object.assign(new Error('x'), {
      name: 'ValidationError',
      data: { errors: [{ path: 'roles', message: 'required' }] },
    })
    expectRepositoryError(
      await repository({ create: () => Promise.reject(unrelated) }).create(input)
    )
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
    const updateOne = vi.fn(down)
    const users = repository({ find: found([linkedDoc]), update, db: { updateOne } })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    expect(update).not.toHaveBeenCalled()
    expect(updateOne).not.toHaveBeenCalled()
  })

  it('appends the identity, keeping existing rows', async () => {
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(linkedDoc))
    const other = { ...linkedDoc, identities: [{ ...linkedDoc.identities[0], providerId: 'x' }] }
    const users = repository({ find: found([other]), db: { updateOne } })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    expect(updateOne.mock.calls[0]?.[0]).toMatchObject({
      id: userId,
      data: { identities: [{ providerId: 'x' }, { providerId: 'stub', providerUserId: 'stub-1' }] },
    })
  })

  it('links through the scoped adapter write, never through full-document validation (issue #144)', async () => {
    // The host operation path WOULD refuse this document: a legacy row
    // whose `name` predates the host's required `name` field fails
    // full-document validation on ANY Local API update (Payload merges
    // the stored document into the incoming data and validates every
    // field). The link must not depend on unrelated fields.
    const fullDocumentValidation = () =>
      Promise.reject(
        new ValidationError({ errors: [{ path: 'name', message: 'This field is required.' }] })
      )
    const update = vi.fn(fullDocumentValidation)
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(linkedDoc))
    const users = repository({ find: found([doc]), update, db: { updateOne } })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    // The full-document operation never ran: its validation never saw
    // the legacy row.
    expect(update).not.toHaveBeenCalled()
    // ONLY plugin-owned fields are written — no host field, no marker
    // (the adapter runs no hooks, so there is nothing to skip).
    const call = updateOne.mock.calls[0]?.[0] as {
      data: Record<string, unknown>
      context?: unknown
    }
    expect(Object.keys(call.data).sort()).toEqual(['identities'])
    expect(call.context).toBeUndefined()
  })

  it('clears Payload local sessions when the collection keeps them (useSessions)', async () => {
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(linkedDoc))
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'admin'],
      defaultRole: 'user',
      providers: [createStubProvider().provider],
    })
    const users = createPayloadUserRepository({
      payload: {
        collections: { users: { config: { auth: { useSessions: true } } } },
        find: found([doc]),
        findByID: () => Promise.resolve({}),
        db: { updateOne },
      } as unknown as Payload,
      map: wired.config.map,
      defaultRole: wired.config.defaultRole,
      logger: wired.logger,
      clock: wired.clock,
      ids: wired.ids,
      depth: wired.depth,
    })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    expect(updateOne.mock.calls[0]?.[0]).toMatchObject({ data: { sessions: [] } })
  })

  it('leaves sessions alone when the collection keeps none', async () => {
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(linkedDoc))
    const users = repository({ find: found([doc]), db: { updateOne } })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    const data = (updateOne.mock.calls[0]?.[0] as { data: Record<string, unknown> }).data
    expect('sessions' in data).toBe(false)
  })

  it('clears the API key AND its Payload lookup index (the index hook does not run here)', async () => {
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(linkedDoc))
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'admin'],
      defaultRole: 'user',
      providers: [createStubProvider().provider],
    })
    const users = createPayloadUserRepository({
      payload: {
        collections: {
          users: {
            config: {
              auth: { useAPIKey: true },
              fields: [{ name: 'enableAPIKey', type: 'checkbox' }],
            },
          },
        },
        find: found([doc]),
        findByID: () => Promise.resolve({}),
        db: { updateOne },
      } as unknown as Payload,
      map: wired.config.map,
      defaultRole: wired.config.defaultRole,
      logger: wired.logger,
      clock: wired.clock,
      ids: wired.ids,
      depth: wired.depth,
    })
    expect((await users.linkIdentity(userId, ref)).isOk()).toBe(true)
    // Payload's Local API nulls `apiKeyIndex` through the
    // `setAPIKeyIndex` field hook on `apiKey: null`; the adapter path
    // runs no hooks, so the scoped write clears the HMAC lookup
    // column itself — the API-key strategy matches on it alone. The
    // write is SPLIT: plain columns through the adapter's
    // plain-UPDATE path, array child rows through the rewrite (a
    // mixed payload would upsert the main row from partial data and
    // trip NOT NULL on the untouched columns).
    expect(updateOne.mock.calls[0]?.[0]).toMatchObject({
      data: { apiKey: null, apiKeyIndex: null, enableAPIKey: false },
    })
    expect(updateOne.mock.calls[1]?.[0]).toMatchObject({
      data: { identities: [expect.objectContaining({ providerUserId: 'stub-1' })] },
    })
    expect(updateOne).toHaveBeenCalledTimes(2)
  })

  it('maps write outages and unmappable results to RepositoryError', async () => {
    expectRepositoryError(
      await repository({ find: found([doc]), db: { updateOne: down } }).linkIdentity(userId, ref)
    )
    expectRepositoryError(
      await repository({
        find: found([doc]),
        db: { updateOne: () => Promise.resolve(null) },
      }).linkIdentity(userId, ref)
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
    expect(warn.some((message) => message.includes('created outside payload-auth-link'))).toBe(true)
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

  it('refuses documents Payload verified but never marked linkable (_verified is not proof)', async () => {
    // Payload keeps `_verified` across email changes: a verified
    // document re-pointed at a victim's address must not be linked.
    const verified = { ...doc, linkable: false, linkableEmail: undefined, _verified: true }
    const warnings: string[] = []
    const base = nullLogger()
    const logger: LoggerPort = {
      ...base,
      warn: (message) => warnings.push(message),
      child: () => logger,
    }
    const users = repository(
      { find: found([verified]), findByID: () => Promise.resolve({}) },
      logger
    )
    expect((await users.findByEmail(email('linked@test.dev')))._unsafeUnwrap()).toBeNull()
    expect(warnings.some((message) => message.includes("Payload's verified flag is not one"))).toBe(
      true
    )
  })

  it('refuses a verified document whose linkable proof is bound to another email', async () => {
    const moved = {
      ...doc,
      email: 'victim@test.dev',
      linkable: true,
      linkableEmail: 'attacker@test.dev',
      _verified: true,
    }
    const users = repository({ find: found([moved]), findByID: () => Promise.resolve({}) })
    expect((await users.findByEmail(email('victim@test.dev')))._unsafeUnwrap()).toBeNull()
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
    const updateOne = vi.fn(down)
    const users = repository({ find: found([doc]), update, db: { updateOne } })
    expect((await users.unlinkIdentity(userId, ref)).isOk()).toBe(true)
    expect(update).not.toHaveBeenCalled()
    expect(updateOne).not.toHaveBeenCalled()
  })

  it('removes only the matching row and never deletes the user', async () => {
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(doc))
    const users = repository({ find: found([linkedDoc]), db: { updateOne } })
    const result = await users.unlinkIdentity(userId, ref)
    expect(result._unsafeUnwrap().identities).toEqual([])
    expect(updateOne.mock.calls[0]?.[0]).toMatchObject({ id: userId, data: { identities: [] } })
  })

  it('scopes the write to the identities field (issue #144)', async () => {
    const update = vi.fn(down)
    const updateOne = vi.fn<(args: unknown) => Promise<unknown>>(() => Promise.resolve(doc))
    const users = repository({ find: found([linkedDoc]), update, db: { updateOne } })
    expect((await users.unlinkIdentity(userId, ref)).isOk()).toBe(true)
    const call = updateOne.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(Object.keys(call.data).sort()).toEqual(['identities'])
  })

  it('maps write outages and unmappable results to RepositoryError', async () => {
    expectRepositoryError(
      await repository({ find: found([linkedDoc]), db: { updateOne: down } }).unlinkIdentity(
        userId,
        ref
      )
    )
    expectRepositoryError(
      await repository({
        find: found([linkedDoc]),
        db: { updateOne: () => Promise.resolve(null) },
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

describe('payload user repository write observer (issue #116)', () => {
  it('reports each performed write once, and never a no-op, a lost race, or a failure', async () => {
    const writes: UserDocumentWrite[] = []
    const observe = (stub: PayloadStub) =>
      repository(stub, undefined, (write) => {
        writes.push(write)
      })
    const newUser = { email: email('linked@test.dev'), roles: [parseRole('user')._unsafeUnwrap()] }
    // Performed writes.
    await observe({ create: () => Promise.resolve(doc) }).create(newUser)
    await observe({
      find: found([doc]),
      db: { updateOne: () => Promise.resolve(linkedDoc) },
    }).linkIdentity(userId, ref)
    await observe({
      find: found([doc]),
      update: () => Promise.resolve({ ...doc, email: 'next@test.dev' }),
    }).setEmail(userId, email('next@test.dev'))
    let call = 0
    const phoneFind = () => {
      call += 1
      return Promise.resolve({ docs: call === 1 ? [doc] : [] })
    }
    await observe({ find: phoneFind, update: () => Promise.resolve(doc) }).setPhone?.(
      userId,
      parsePhoneNumber('+14155550132')._unsafeUnwrap()
    )
    expect(writes).toEqual([
      { operation: 'create', userId: 'user-1' },
      { operation: 'linkIdentity', userId: 'user-1' },
      { operation: 'setEmail', userId: 'user-1' },
      { operation: 'setPhone', userId: 'user-1' },
    ])
    writes.length = 0
    // No-ops, a lost create race, and a failed write report nothing.
    await observe({ create: uniqueEmailViolation }).create(newUser)
    await observe({ find: found([linkedDoc]), db: { updateOne: down } }).linkIdentity(userId, ref)
    await observe({ find: found([doc]), update: down }).setEmail(userId, email('linked@test.dev'))
    await observe({ find: found([doc]), update: down }).setEmail(userId, email('next@test.dev'))
    expect(writes).toEqual([])
  })
})

describe('payload user repository write marker (issue #144 part 2)', () => {
  it('stamps resync-email on the setEmail write so host hooks can skip it', async () => {
    const writes: Array<Record<string, unknown> | undefined> = []
    const users = repository({
      find: found([linkedDoc]),
      update: (args: unknown) => {
        writes.push(args as Record<string, unknown>)
        return Promise.resolve({ ...linkedDoc, email: 'next@test.dev' })
      },
    })
    expect((await users.setEmail(userId, email('next@test.dev'))).isOk()).toBe(true)
    expect(writes[0]?.context).toEqual({ [authLinkWriteMarker]: { op: 'resync-email' } })
  })

  it('stamps resync-phone on the setPhone write', async () => {
    const writes: Array<Record<string, unknown> | undefined> = []
    let call = 0
    const find = () => {
      call += 1
      return Promise.resolve({ docs: call === 1 ? [doc] : [] })
    }
    const users = repository({
      find,
      update: (args: unknown) => {
        writes.push(args as Record<string, unknown>)
        return Promise.resolve({ ...doc, phone: '+14155550132' })
      },
    })
    expect(
      (await users.setPhone?.(userId, parsePhoneNumber('+14155550132')._unsafeUnwrap()))?.isOk()
    ).toBe(true)
    expect(writes[0]?.context).toEqual({ [authLinkWriteMarker]: { op: 'resync-phone' } })
  })

  it('stamps set-roles on the setRoles write', async () => {
    const writes: Array<Record<string, unknown> | undefined> = []
    const users = repository({
      update: (args: unknown) => {
        writes.push(args as Record<string, unknown>)
        return Promise.resolve({ ...doc, roles: ['admin'] })
      },
    })
    expect((await users.setRoles(userId, [parseRole('admin')._unsafeUnwrap()])).isOk()).toBe(true)
    expect(writes[0]?.context).toEqual({ [authLinkWriteMarker]: { op: 'set-roles' } })
  })

  it('stamps create beside the linkable-create proof marker', async () => {
    const writes: Array<Record<string, unknown> | undefined> = []
    const users = repository({
      create: (args: unknown) => {
        writes.push(args as Record<string, unknown>)
        return Promise.resolve(doc)
      },
    })
    expect(
      (
        await users.create({
          email: email('linked@test.dev'),
          roles: [parseRole('user')._unsafeUnwrap()],
        })
      ).isOk()
    ).toBe(true)
    expect(writes[0]?.context).toEqual({
      [linkableCreateMarker]: true,
      [authLinkWriteMarker]: { op: 'create' },
    })
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

describe('linkIdentity runs in an adapter transaction (issue #144 scoping)', () => {
  it('commits the transaction and carries it on the scoped write', async () => {
    const seen: unknown[] = []
    const repo = repository(
      {
        find: found([
          {
            id: 'u1',
            email: 'tx@test.dev',
            identities: [],
            roles: ['user'],
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ]),
        findByID: () =>
          Promise.resolve({
            id: 'u1',
            email: 'tx@test.dev',
            identities: [],
            roles: ['user'],
            createdAt: new Date(),
            updatedAt: new Date(),
          }),
        db: {
          beginTransaction: () => Promise.resolve('tx-7'),
          commitTransaction: () => Promise.resolve(),
          rollbackTransaction: () => Promise.resolve(),
          updateOne: (args) => {
            seen.push(args)
            return Promise.resolve(user)
          },
        },
      } as PayloadStub,
      undefined,
      () => undefined
    )
    const result = await repo.linkIdentity('u1' as never, {
      providerId: 'stub' as never,
      providerUserId: 'ba-9',
    })
    if (result.isErr()) {
    }
    expect(result.isOk()).toBe(true)
    expect(seen).toHaveLength(1)
    const write = seen[0] as { req?: { transactionID?: string } }
    expect(write.req?.transactionID).toBe('tx-7')
  })

  it('rolls the transaction back and rethrows when the scoped write fails', async () => {
    let rolledBack = false
    const repo = repository({
      find: found([
        {
          id: 'u1',
          email: 'tx@test.dev',
          identities: [],
          roles: ['user'],
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ]),
      findByID: () =>
        Promise.resolve({
          id: 'u1',
          email: 'tx@test.dev',
          identities: [],
          roles: ['user'],
          createdAt: new Date(),
          updatedAt: new Date(),
        }),
      db: {
        beginTransaction: () => Promise.resolve('tx-8'),
        commitTransaction: () => Promise.resolve(),
        rollbackTransaction: () => {
          rolledBack = true
          return Promise.resolve()
        },
        updateOne: () => Promise.reject(new Error('storage gone')),
      },
    } as PayloadStub)
    const result = await repo.linkIdentity('u1' as never, {
      providerId: 'stub' as never,
      providerUserId: 'ba-9',
    })
    expect(result.isErr()).toBe(true)
    expect(rolledBack).toBe(true)
  })
})
