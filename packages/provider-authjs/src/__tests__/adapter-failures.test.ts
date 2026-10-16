/**
 * Auth.js adapter fail-loud contract (issue #110): every document the
 * adapter cannot honestly map raises `AdapterMappingError`, and every
 * Local API failure raises `AdapterOperationError` wrapping its cause —
 * never a `null` that Auth.js would read as "no such user / session /
 * token" (which, for a session or verification token, is a silent
 * logout or a silently unconsumed magic link at best).
 *
 * Driven against a scripted Payload double; the success paths run on
 * real Payload in `adapter-conformance.test.ts` and `engine.test.ts`.
 */
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { createAuthJsAdapter } from '../adapter.js'
import { AdapterMappingError, AdapterOperationError } from '../errors.js'

type Script = {
  find?: () => Promise<{ docs: unknown[] }>
  create?: () => Promise<unknown>
  update?: () => Promise<unknown>
  delete?: () => Promise<unknown>
}

function adapterWith(script: Script) {
  const payload = {
    find: vi.fn(script.find ?? (() => Promise.resolve({ docs: [] }))),
    create: vi.fn(script.create ?? (() => Promise.resolve({}))),
    update: vi.fn(script.update ?? (() => Promise.resolve({}))),
    delete: vi.fn(script.delete ?? (() => Promise.resolve({}))),
  }
  const adapter = createAuthJsAdapter({
    getPayload: () => Promise.resolve(payload as unknown as Payload),
  })
  return { adapter, payload }
}

const found =
  (...docs: unknown[]) =>
  () =>
    Promise.resolve({ docs })
const rejects = () => Promise.reject(new Error('db down'))
const returnsNull = () => Promise.resolve(null)

const userDoc = { id: 1, auId: 'au-1', email: 'a@b.co', emailVerified: null }
const sessionDoc = {
  id: 2,
  sessionToken: 'st-1',
  userId: 'au-1',
  expires: '2030-01-01T00:00:00.000Z',
}
const accountDoc = {
  id: 3,
  provider: 'github',
  providerAccountId: 'gh-1',
  userId: 'au-1',
  type: 'oauth',
}
const authenticatorDoc = {
  id: 4,
  credentialID: 'cred-1',
  userId: 'au-1',
  providerAccountId: 'pa-1',
  credentialPublicKey: 'pk',
  counter: 1,
  credentialBackedUp: false,
  credentialDeviceType: 'singleDevice',
}
const expires = new Date('2030-01-01T00:00:00.000Z')

describe('document mapping fails loud', () => {
  it.each([
    ['a missing auId', { ...userDoc, auId: undefined }, /auId is missing/],
    ['an empty email', { ...userDoc, email: '' }, /email is missing/],
    ['a non-string emailVerified', { ...userDoc, emailVerified: 1 }, /not a date string/],
    ['an invalid emailVerified date', { ...userDoc, emailVerified: 'soon' }, /not a valid date/],
  ])('a user row with %s', async (_label, doc, message) => {
    const { adapter } = adapterWith({ find: found(doc) })
    await expect(adapter.getUser?.('au-1')).rejects.toThrow(message)
    await expect(adapter.getUser?.('au-1')).rejects.toBeInstanceOf(AdapterMappingError)
  })

  it('a session row with no expiry is a mapping error, never a non-expiring session', async () => {
    const { adapter } = adapterWith({ find: found({ ...sessionDoc, expires: null }) })
    await expect(adapter.getSessionAndUser?.('st-1')).rejects.toThrow(/expires is missing/)
  })

  it('a verification token with no expiry is a mapping error, and stays unconsumed', async () => {
    const { adapter, payload } = adapterWith({
      find: found({ id: 5, identifier: 'a@b.co', token: 't', expires: undefined }),
    })
    await expect(
      adapter.useVerificationToken?.({ identifier: 'a@b.co', token: 't' })
    ).rejects.toBeInstanceOf(AdapterMappingError)
    expect(payload.delete).not.toHaveBeenCalled()
  })

  it('a non-object document from find is a mapping error', async () => {
    const { adapter } = adapterWith({ find: found('not-a-doc') })
    await expect(adapter.getUserByEmail?.('a@b.co')).rejects.toThrow(/document is not an object/)
  })

  it('a non-object document in a list is a mapping error', async () => {
    const { adapter } = adapterWith({ find: found(authenticatorDoc, 42) })
    await expect(adapter.listAuthenticatorsByUserId?.('au-1')).rejects.toThrow(
      /document is not an object/
    )
  })

  it('an account with no userId refuses getUserByAccount', async () => {
    const { adapter } = adapterWith({ find: found({ ...accountDoc, userId: 9 }) })
    await expect(
      adapter.getUserByAccount?.({ provider: 'github', providerAccountId: 'gh-1' })
    ).rejects.toThrow(/account has no userId/)
  })

  it('an account with an unknown type is a mapping error', async () => {
    const { adapter } = adapterWith({ find: found({ ...accountDoc, type: 'magic' }) })
    await expect(adapter.getAccount?.('gh-1', 'github')).rejects.toThrow(/unknown value "magic"/)
  })

  it('an authenticator with mistyped counter fields is a mapping error', async () => {
    const { adapter } = adapterWith({ find: found({ ...authenticatorDoc, counter: '1' }) })
    await expect(adapter.getAuthenticator?.('cred-1')).rejects.toThrow(/wrong types/)
  })

  it('a document with no id cannot be deleted or updated', async () => {
    const noId = { ...sessionDoc, id: undefined }
    const { adapter } = adapterWith({ find: found(noId) })
    await expect(adapter.deleteSession?.('st-1')).rejects.toThrow(/document has no id/)
    await expect(adapter.updateSession?.({ sessionToken: 'st-1', expires })).rejects.toThrow(
      /document has no id/
    )
  })

  it('an update that returns no document is a mapping error', async () => {
    const { adapter } = adapterWith({ find: found(userDoc), update: returnsNull })
    await expect(adapter.updateUser?.({ id: 'au-1', name: 'n' })).rejects.toThrow(
      /update returned no document/
    )
  })

  it.each([
    [
      'createUser',
      (a: ReturnType<typeof adapterWith>['adapter']) =>
        a.createUser?.({ id: 'au-1', email: 'a@b.co', emailVerified: null }),
    ],
    [
      'linkAccount',
      (a: ReturnType<typeof adapterWith>['adapter']) =>
        a.linkAccount?.({
          provider: 'github',
          providerAccountId: 'gh-1',
          userId: 'au-1',
          type: 'oauth',
        }),
    ],
    [
      'createSession',
      (a: ReturnType<typeof adapterWith>['adapter']) =>
        a.createSession?.({ sessionToken: 'st-1', userId: 'au-1', expires }),
    ],
    [
      'createVerificationToken',
      (a: ReturnType<typeof adapterWith>['adapter']) =>
        a.createVerificationToken?.({ identifier: 'a@b.co', token: 't', expires }),
    ],
    [
      'createAuthenticator',
      (a: ReturnType<typeof adapterWith>['adapter']) =>
        a.createAuthenticator?.({
          credentialID: 'cred-1',
          userId: 'au-1',
          providerAccountId: 'pa-1',
          credentialPublicKey: 'pk',
          counter: 0,
          credentialBackedUp: false,
          credentialDeviceType: 'singleDevice',
        }),
    ],
  ])('%s: a create that returns no document is a mapping error', async (operation, call) => {
    const { adapter } = adapterWith({ create: returnsNull })
    await expect(call(adapter)).rejects.toThrow(
      new RegExp(`${operation}: create returned no document`)
    )
  })
})

describe('Local API failures surface as AdapterOperationError', () => {
  it('a failed read is an operation error, never "not found"', async () => {
    const { adapter } = adapterWith({ find: rejects })
    const failure = adapter.getSessionAndUser?.('st-1')
    await expect(failure).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(adapter.getSessionAndUser?.('st-1')).rejects.toMatchObject({
      cause: expect.objectContaining({ message: 'db down' }) as unknown,
    })
    await expect(adapter.listAuthenticatorsByUserId?.('au-1')).rejects.toBeInstanceOf(
      AdapterOperationError
    )
  })

  it('failed writes are operation errors', async () => {
    const { adapter } = adapterWith({
      find: found(sessionDoc),
      create: rejects,
      update: rejects,
      delete: rejects,
    })
    await expect(
      adapter.createUser?.({ id: 'au-1', email: 'a@b.co', emailVerified: null })
    ).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(
      adapter.linkAccount?.({
        provider: 'github',
        providerAccountId: 'gh-1',
        userId: 'au-1',
        type: 'oauth',
      })
    ).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(
      adapter.createSession?.({ sessionToken: 'st-1', userId: 'au-1', expires })
    ).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(
      adapter.createVerificationToken?.({ identifier: 'a@b.co', token: 't', expires })
    ).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(
      adapter.createAuthenticator?.({
        credentialID: 'cred-1',
        userId: 'au-1',
        providerAccountId: 'pa-1',
        credentialPublicKey: 'pk',
        counter: 0,
        credentialBackedUp: false,
        credentialDeviceType: 'singleDevice',
      })
    ).rejects.toBeInstanceOf(AdapterOperationError)
    // A failed delete must not read as a revoked session.
    await expect(adapter.deleteSession?.('st-1')).rejects.toBeInstanceOf(AdapterOperationError)
    await expect(adapter.updateSession?.({ sessionToken: 'st-1', expires })).rejects.toBeInstanceOf(
      AdapterOperationError
    )
  })

  it('updates on missing rows fail loudly instead of creating them', async () => {
    const { adapter, payload } = adapterWith({ find: found() })
    await expect(adapter.updateUser?.({ id: 'au-x', name: 'n' })).rejects.toThrow(
      /updateUser on a missing user/
    )
    await expect(adapter.updateAuthenticatorCounter?.('cred-x', 2)).rejects.toThrow(
      /missing authenticator/
    )
    expect(payload.update).not.toHaveBeenCalled()
    expect(payload.create).not.toHaveBeenCalled()
  })
})

describe('optional fields round-trip without inventing values', () => {
  it('an account keeps only the typed token fields it stored', async () => {
    const { adapter } = adapterWith({
      find: found({
        ...accountDoc,
        access_token: 'at',
        refresh_token: 'rt',
        id_token: 'it',
        token_type: 'bearer',
        scope: 'read',
        session_state: 'ss',
        expires_at: 1234,
      }),
    })
    expect(await adapter.getAccount?.('gh-1', 'github')).toEqual({
      provider: 'github',
      providerAccountId: 'gh-1',
      userId: 'au-1',
      type: 'oauth',
      access_token: 'at',
      refresh_token: 'rt',
      id_token: 'it',
      token_type: 'bearer',
      scope: 'read',
      session_state: 'ss',
      expires_at: 1234,
    })
  })

  it('an account with a non-numeric expires_at drops it', async () => {
    const { adapter } = adapterWith({ find: found({ ...accountDoc, expires_at: '1234' }) })
    expect(await adapter.getAccount?.('gh-1', 'github')).not.toHaveProperty('expires_at')
  })

  it('an authenticator keeps its transports when stored', async () => {
    const { adapter } = adapterWith({ find: found({ ...authenticatorDoc, transports: 'usb' }) })
    expect((await adapter.getAuthenticator?.('cred-1'))?.transports).toBe('usb')
  })

  it('a user patch writes only the fields present, clearing emailVerified on null', async () => {
    const { adapter, payload } = adapterWith({
      find: found(userDoc),
      update: () => Promise.resolve(userDoc),
    })
    await adapter.updateUser?.({ id: 'au-1', image: 'img', emailVerified: null })
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { image: 'img', emailVerified: null } })
    )
  })

  it('a session patch writes the new owner and expiry', async () => {
    const { adapter, payload } = adapterWith({
      find: found(sessionDoc),
      update: () => Promise.resolve(sessionDoc),
    })
    await adapter.updateSession?.({ sessionToken: 'st-1', userId: 'au-2', expires })
    expect(payload.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { userId: 'au-2', expires: expires.toISOString() } })
    )
  })
})
