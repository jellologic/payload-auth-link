import { InvalidEmailError, UserExistsError } from '@payload-auth-link/core'
import { scryptSync } from 'node:crypto'
import type { Payload } from 'payload'
import { describe, expect, it, vi, type Mock } from 'vitest'

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>()
  return { ...actual, scryptSync: vi.fn(actual.scryptSync) as typeof actual.scryptSync }
})

function scryptCalls(): number {
  return vi.mocked(scryptSync).mock.calls.length
}
import {
  createAuthJsCredentials,
  hashCredentialsPassword,
  minCredentialsPasswordLength,
  verifyCredentialsPassword,
} from '../credentials.js'
import { AdapterMappingError, AdapterOperationError, WeakPasswordError } from '../errors.js'

type UserRow = {
  auId?: unknown
  email?: unknown
  name?: string
  passwordHash?: unknown
  emailVerified?: string
}

type FindMock = Mock<
  (args: {
    where?: { email?: { equals?: string } }
  }) => Promise<{ docs: unknown[]; totalDocs: number }>
>
type CreateMock = Mock<
  (args: { data: Record<string, unknown> }) => Promise<Record<string, unknown>>
>

function fakePayload(rows: Record<string, UserRow> = {}): {
  payload: Payload
  find: FindMock
  create: CreateMock
} {
  const find: FindMock = vi.fn(({ where }: { where?: { email?: { equals?: string } } }) => {
    const email = where?.email?.equals
    const row = email === undefined ? undefined : rows[email]
    return Promise.resolve({
      docs: row === undefined ? [] : [row],
      totalDocs: row === undefined ? 0 : 1,
    })
  })
  const create: CreateMock = vi.fn(({ data }: { data: Record<string, unknown> }) =>
    Promise.resolve({ ...data, id: 'doc-1' })
  )
  return { payload: { find, create } as unknown as Payload, find, create }
}

describe('password hashing', () => {
  it('round-trips and salts uniquely', () => {
    const first = hashCredentialsPassword('hunter2')
    const second = hashCredentialsPassword('hunter2')
    expect(first).not.toBe(second)
    expect(verifyCredentialsPassword('hunter2', first)).toBe(true)
    expect(verifyCredentialsPassword('hunter3', first)).toBe(false)
  })

  it('fails closed on malformed hashes', () => {
    expect(verifyCredentialsPassword('hunter2', 'not-a-hash')).toBe(false)
    expect(verifyCredentialsPassword('hunter2', '')).toBe(false)
  })
})

describe('createAuthJsCredentials config', () => {
  it('rejects minimum lengths below the floor', () => {
    const { payload } = fakePayload()
    expect(() =>
      createAuthJsCredentials({ getPayload: () => Promise.resolve(payload), minPasswordLength: 4 })
    ).toThrow(`minPasswordLength must be at least ${minCredentialsPasswordLength}`)
    expect(minCredentialsPasswordLength).toBe(8)
  })

  it('rejects empty slug overrides at wiring time', () => {
    const { payload } = fakePayload()
    expect(() =>
      createAuthJsCredentials({
        getPayload: () => Promise.resolve(payload),
        slugs: { user: '' },
      })
    ).toThrow('slug for model "user" must be a non-empty string')
  })
})

describe('authorize', () => {
  it('authorizes known users and smuggles verification for the jwt callback', async () => {
    const { payload, find } = fakePayload({
      'a@b.co': {
        auId: 'au-1',
        email: 'a@b.co',
        name: 'A',
        passwordHash: hashCredentialsPassword('sekret!!'),
        emailVerified: '2026-01-02T00:00:00.000Z',
      },
    })
    const { authorize } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const user = await authorize({ email: 'a@b.co', password: 'sekret!!' })
    expect(user).toMatchObject({ id: 'au-1', email: 'a@b.co', name: 'A' })
    // `User` carries no verification field; the claim rides untyped to the
    // jwt callback, so read it back through an unknown-shaped lens.
    const claims = user as unknown as { emailVerified?: unknown }
    expect(claims.emailVerified).toEqual(new Date('2026-01-02T00:00:00.000Z'))
    expect(find).toHaveBeenCalledTimes(1)
  })

  it('burns a full scrypt for unknown users and hashless rows (no enumeration oracle)', async () => {
    const { payload } = fakePayload({
      'hashless@b.co': { auId: 'au-9', email: 'hashless@b.co' },
    })
    const { authorize } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const before = scryptCalls()
    await expect(authorize({ email: 'ghost@b.co', password: 'sekret!!' })).resolves.toBeNull()
    await expect(authorize({ email: 'hashless@b.co', password: 'sekret!!' })).resolves.toBeNull()
    // One dummy verification per path — the same cost as a wrong password.
    expect(scryptCalls() - before).toBe(2)
  })

  it('returns null for unknown users, wrong passwords, and malformed input', async () => {
    const { payload } = fakePayload({
      'a@b.co': {
        auId: 'au-1',
        email: 'a@b.co',
        passwordHash: hashCredentialsPassword('sekret!!'),
      },
    })
    const { authorize } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    await expect(authorize({ email: 'ghost@b.co', password: 'sekret!!' })).resolves.toBeNull()
    await expect(authorize({ email: 'a@b.co', password: 'nope!!!!' })).resolves.toBeNull()
    await expect(authorize(undefined)).resolves.toBeNull()
    await expect(authorize({})).resolves.toBeNull()
    await expect(authorize({ email: 'a@b.co' })).resolves.toBeNull()
    await expect(authorize({ email: 'a@b.co', password: 42 })).resolves.toBeNull()
    await expect(authorize({ email: '', password: 'sekret!!' })).resolves.toBeNull()
  })

  it('normalizes the email before lookup (SEC-11)', async () => {
    const { payload, find } = fakePayload({
      'user@x.com': {
        auId: 'au-2',
        email: 'user@x.com',
        passwordHash: hashCredentialsPassword('sekret!!'),
      },
    })
    const { authorize } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const user = await authorize({ email: 'User@X.com', password: 'sekret!!' })
    expect(user).toMatchObject({ id: 'au-2', email: 'user@x.com' })
    expect(find.mock.calls[0]?.[0].where?.email?.equals).toBe('user@x.com')
  })

  it('fails malformed emails closed through the dummy verification', async () => {
    const { payload, find } = fakePayload()
    const { authorize } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const before = scryptCalls()
    await expect(authorize({ email: 'not-an-email', password: 'sekret!!' })).resolves.toBeNull()
    expect(scryptCalls() - before).toBe(1)
    expect(find).not.toHaveBeenCalled()
  })

  it('throws AdapterMappingError on a corrupt emailVerified stamp (TYP-5)', async () => {
    const { payload } = fakePayload({
      'a@b.co': {
        auId: 'au-1',
        email: 'a@b.co',
        passwordHash: hashCredentialsPassword('sekret!!'),
        emailVerified: 'not-a-date',
      },
    })
    const { authorize } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    await expect(authorize({ email: 'a@b.co', password: 'sekret!!' })).rejects.toThrow(
      /emailVerified is not a valid date/
    )
  })

  it('throws loudly on corrupt rows and wraps infra failures', async () => {
    const corrupt = fakePayload({ 'a@b.co': { email: 'a@b.co' } })
    const broken = createAuthJsCredentials({ getPayload: () => Promise.resolve(corrupt.payload) })
    await expect(broken.authorize({ email: 'a@b.co', password: 'x' })).rejects.toThrow(
      AdapterMappingError
    )

    const exploding = {
      find: vi.fn((): Promise<never> => Promise.reject(new Error('db down'))),
    } as unknown as Payload
    const infra = createAuthJsCredentials({ getPayload: () => Promise.resolve(exploding) })
    await expect(infra.authorize({ email: 'a@b.co', password: 'x' })).rejects.toThrow(
      AdapterOperationError
    )

    const noPayload = createAuthJsCredentials({
      getPayload: () => Promise.reject(new Error('no payload')),
    })
    await expect(noPayload.authorize({ email: 'a@b.co', password: 'x' })).rejects.toThrow(
      AdapterOperationError
    )
  })
})

describe('register', () => {
  it('writes the user row with a hash and defaults to unverified', async () => {
    const { payload, create } = fakePayload()
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({ email: 'New@b.co', password: 'sekret!!', name: 'New' })
    expect(result.isOk()).toBe(true)
    if (result.isErr()) {
      throw new Error('expected ok')
    }
    expect(result.value.email).toBe('new@b.co')
    expect(result.value.id).toEqual(expect.any(String))
    expect(create).toHaveBeenCalledTimes(1)
    const data = create.mock.calls[0]?.[0].data
    expect(data?.email).toBe('new@b.co')
    expect(data?.name).toBe('New')
    expect(typeof data?.passwordHash).toBe('string')
    if (typeof data?.passwordHash === 'string') {
      expect(verifyCredentialsPassword('sekret!!', data.passwordHash)).toBe(true)
    }
    expect(data?.emailVerified).toBeUndefined()
  })

  it('stamps builder-provided verification', async () => {
    const { payload, create } = fakePayload()
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({
      email: 'a@b.co',
      password: 'sekret!!',
      emailVerified: new Date('2026-01-02T00:00:00.000Z'),
    })
    expect(result.isOk()).toBe(true)
    const data = create.mock.calls[0]?.[0].data
    expect(data?.emailVerified).toBe('2026-01-02T00:00:00.000Z')
  })

  it('returns InvalidEmailError for bad emails', async () => {
    const { payload, find } = fakePayload()
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({ email: 'not-an-email', password: 'sekret!!' })
    expect(result.isErr()).toBe(true)
    if (result.isOk()) {
      throw new Error('expected err')
    }
    expect(result.error).toBeInstanceOf(InvalidEmailError)
    expect(find).not.toHaveBeenCalled()
  })

  it('returns WeakPasswordError for short passwords', async () => {
    const { payload, find } = fakePayload()
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({ email: 'a@b.co', password: 'short' })
    expect(result.isErr()).toBe(true)
    if (result.isOk()) {
      throw new Error('expected err')
    }
    expect(result.error).toBeInstanceOf(WeakPasswordError)
    expect(find).not.toHaveBeenCalled()
  })

  it('returns UserExistsError for duplicates', async () => {
    const { payload } = fakePayload({
      'taken@b.co': {
        auId: 'au-1',
        email: 'taken@b.co',
        passwordHash: hashCredentialsPassword('sekret!!'),
      },
    })
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({ email: 'taken@b.co', password: 'sekret!!' })
    expect(result.isErr()).toBe(true)
    if (result.isOk()) {
      throw new Error('expected err')
    }
    expect(result.error).toBeInstanceOf(UserExistsError)
  })

  it('returns AdapterOperationError with cause for storage failures', async () => {
    const find = vi.fn(() => Promise.resolve({ docs: [], totalDocs: 0 }))
    const create = vi.fn((): Promise<never> => Promise.reject(new Error('db down')))
    const payload = { find, create } as unknown as Payload
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({ email: 'a@b.co', password: 'sekret!!' })
    expect(result.isErr()).toBe(true)
    if (result.isOk()) {
      throw new Error('expected err')
    }
    expect(result.error).toBeInstanceOf(AdapterOperationError)
    expect(result.error.message).toContain('credentials register')
    expect(result.error.cause).toBeInstanceOf(Error)
  })

  it('returns AdapterOperationError when reads fail', async () => {
    const find = vi.fn((): Promise<never> => Promise.reject(new Error('db down')))
    const payload = { find } as unknown as Payload
    const { register } = createAuthJsCredentials({ getPayload: () => Promise.resolve(payload) })
    const result = await register({ email: 'a@b.co', password: 'sekret!!' })
    expect(result.isErr()).toBe(true)
    if (result.isOk()) {
      throw new Error('expected err')
    }
    expect(result.error).toBeInstanceOf(AdapterOperationError)
  })
})
