/**
 * Adapter tests: the full Auth.js adapter lifecycle against real Payload
 * storage (SQLite in memory), plus error mapping against a stubbed Local
 * API. Every adapter method is exercised; deleteUser proves the explicit
 * cascade (Payload has no cascades of its own).
 */
import type {
  Adapter,
  AdapterAccount,
  AdapterAuthenticator,
  AdapterUser,
} from '@auth/core/adapters'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { createAuthJsAdapter } from '../adapter.js'
import { createAuthJsCollections, defaultAuthJsSlugs } from '../collections.js'
import { AdapterMappingError, AdapterOperationError } from '../errors.js'

const SECRET = 'authjs-adapter-integration-secret!!'
const FUTURE = new Date('2027-01-01T00:00:00.000Z')
const LATER = new Date('2027-06-01T00:00:00.000Z')

let payload: Payload
let adapter: Adapter

function userInput(email: string, overrides: Partial<AdapterUser> = {}): AdapterUser {
  // An empty id exercises the adapter's UUID generation; pass an explicit
  // id to pin it.
  return { id: '', email, emailVerified: null, ...overrides }
}

function accountFixture(userId: string, overrides: Partial<AdapterAccount> = {}): AdapterAccount {
  return {
    provider: 'github',
    providerAccountId: 'gh-123',
    userId,
    type: 'oauth',
    access_token: 'at-1',
    scope: 'read:user',
    expires_at: Math.floor(FUTURE.getTime() / 1000),
    ...overrides,
  }
}

function authenticatorFixture(
  userId: string,
  overrides: Partial<AdapterAuthenticator> = {}
): AdapterAuthenticator {
  return {
    credentialID: 'cred-1',
    userId,
    providerAccountId: 'gh-123',
    credentialPublicKey: 'pubkey',
    counter: 0,
    credentialBackedUp: false,
    credentialDeviceType: 'singleDevice',
    transports: 'usb',
    ...overrides,
  }
}

beforeAll(async () => {
  const built: SanitizedConfig = await buildConfig({
    secret: SECRET,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: createAuthJsCollections(),
  })
  payload = await getPayload({ config: built })
  adapter = createAuthJsAdapter({ getPayload: () => Promise.resolve(payload) })
})

describe('user lifecycle', () => {
  it('creates, reads, updates, and patches verification', async () => {
    const created = await adapter.createUser?.(userInput('lifecycle@example.com', { name: 'Life' }))
    expect(created?.id).toEqual(expect.any(String))
    if (created === undefined || created === null) {
      expect.unreachable('createUser returned nothing')
    }
    expect(created.emailVerified).toBeNull()

    await expect(adapter.getUser?.(created.id)).resolves.toMatchObject({
      email: 'lifecycle@example.com',
    })
    await expect(adapter.getUserByEmail?.('lifecycle@example.com')).resolves.toMatchObject({
      id: created.id,
    })
    await expect(adapter.getUser?.('missing')).resolves.toBeNull()
    await expect(adapter.getUserByEmail?.('missing@example.com')).resolves.toBeNull()

    const updated = await adapter.updateUser?.({
      id: created.id,
      email: created.email,
      emailVerified: FUTURE,
      name: 'Renamed',
    })
    expect(updated).toMatchObject({ name: 'Renamed', emailVerified: FUTURE })

    const unverified = await adapter.updateUser?.({
      id: created.id,
      email: created.email,
      emailVerified: null,
    })
    expect(unverified?.emailVerified).toBeNull()
  })

  it('honors builder-provided ids', async () => {
    const created = await adapter.createUser?.(
      userInput('fixed@example.com', { id: 'fixed-au-id' })
    )
    expect(created?.id).toBe('fixed-au-id')
  })
})

describe('account lifecycle', () => {
  it('links, resolves by account, and unlinks', async () => {
    const user = await adapter.createUser?.(userInput('oauth@example.com'))
    if (user === undefined || user === null) {
      expect.unreachable('createUser returned nothing')
    }
    const linked = await adapter.linkAccount?.(accountFixture(user.id))
    expect(linked).toMatchObject({
      provider: 'github',
      providerAccountId: 'gh-123',
      userId: user.id,
      access_token: 'at-1',
    })

    await expect(
      adapter.getUserByAccount?.({ provider: 'github', providerAccountId: 'gh-123' })
    ).resolves.toMatchObject({ id: user.id })
    await expect(
      adapter.getUserByAccount?.({ provider: 'github', providerAccountId: 'nope' })
    ).resolves.toBeNull()
    await expect(adapter.getAccount?.('gh-123', 'github')).resolves.toMatchObject({
      userId: user.id,
    })
    await expect(adapter.getAccount?.('nope', 'github')).resolves.toBeNull()

    await adapter.unlinkAccount?.({ provider: 'github', providerAccountId: 'gh-123' })
    await expect(adapter.getAccount?.('gh-123', 'github')).resolves.toBeNull()
    // Idempotent: unlinking twice is fine.
    await adapter.unlinkAccount?.({ provider: 'github', providerAccountId: 'gh-123' })
  })
})

describe('database session lifecycle', () => {
  it('creates, joins to the user, extends, and deletes', async () => {
    const user = await adapter.createUser?.(userInput('session@example.com'))
    if (user === undefined || user === null) {
      expect.unreachable('createUser returned nothing')
    }
    const session = await adapter.createSession?.({
      sessionToken: 'tok-abc',
      userId: user.id,
      expires: FUTURE,
    })
    expect(session).toMatchObject({ sessionToken: 'tok-abc', userId: user.id })

    const joined = await adapter.getSessionAndUser?.('tok-abc')
    expect(joined?.session.sessionToken).toBe('tok-abc')
    expect(joined?.user.id).toBe(user.id)
    await expect(adapter.getSessionAndUser?.('tok-missing')).resolves.toBeNull()

    const extended = await adapter.updateSession?.({ sessionToken: 'tok-abc', expires: LATER })
    expect(extended?.expires).toEqual(LATER)
    await expect(
      adapter.updateSession?.({ sessionToken: 'tok-missing', expires: LATER })
    ).resolves.toBeNull()

    await adapter.deleteSession?.('tok-abc')
    await expect(adapter.getSessionAndUser?.('tok-abc')).resolves.toBeNull()
    // Idempotent.
    await adapter.deleteSession?.('tok-abc')
  })

  it('returns null when the session outlives its user', async () => {
    const user = await adapter.createUser?.(userInput('orphan@example.com'))
    if (user === undefined || user === null) {
      expect.unreachable('createUser returned nothing')
    }
    await adapter.createSession?.({
      sessionToken: 'tok-orphan',
      userId: 'ghost-au-id',
      expires: FUTURE,
    })
    await expect(adapter.getSessionAndUser?.('tok-orphan')).resolves.toBeNull()
  })
})

describe('verification tokens', () => {
  it('are single-use: claim once, then gone', async () => {
    await adapter.createVerificationToken?.({
      identifier: 'magic@example.com',
      token: 'secret-token',
      expires: FUTURE,
    })
    const claimed = await adapter.useVerificationToken?.({
      identifier: 'magic@example.com',
      token: 'secret-token',
    })
    expect(claimed).toMatchObject({ identifier: 'magic@example.com', token: 'secret-token' })
    await expect(
      adapter.useVerificationToken?.({ identifier: 'magic@example.com', token: 'secret-token' })
    ).resolves.toBeNull()
    await expect(
      adapter.useVerificationToken?.({ identifier: 'magic@example.com', token: 'wrong' })
    ).resolves.toBeNull()
  })
})

describe('authenticator lifecycle', () => {
  it('creates, reads, lists, and bumps counters', async () => {
    const user = await adapter.createUser?.(userInput('passkey@example.com'))
    if (user === undefined || user === null) {
      expect.unreachable('createUser returned nothing')
    }
    await adapter.createAuthenticator?.(authenticatorFixture(user.id))
    await adapter.createAuthenticator?.(authenticatorFixture(user.id, { credentialID: 'cred-2' }))

    await expect(adapter.getAuthenticator?.('cred-1')).resolves.toMatchObject({
      userId: user.id,
      counter: 0,
      transports: 'usb',
    })
    await expect(adapter.getAuthenticator?.('missing')).resolves.toBeNull()

    const listed = await adapter.listAuthenticatorsByUserId?.(user.id)
    expect(listed?.map((entry) => entry.credentialID).sort()).toEqual(['cred-1', 'cred-2'])

    const bumped = await adapter.updateAuthenticatorCounter?.('cred-1', 7)
    expect(bumped?.counter).toBe(7)
  })
})

describe('deleteUser cascade', () => {
  it('removes accounts, sessions, and authenticators with the user', async () => {
    const user = await adapter.createUser?.(userInput('cascade@example.com'))
    if (user === undefined || user === null) {
      expect.unreachable('createUser returned nothing')
    }
    await adapter.linkAccount?.(accountFixture(user.id, { providerAccountId: 'cascade-gh' }))
    await adapter.createSession?.({ sessionToken: 'tok-cascade', userId: user.id, expires: FUTURE })
    await adapter.createAuthenticator?.(
      authenticatorFixture(user.id, { credentialID: 'cascade-cred' })
    )

    await adapter.deleteUser?.(user.id)

    await expect(adapter.getUser?.(user.id)).resolves.toBeNull()
    await expect(adapter.getAccount?.('cascade-gh', 'github')).resolves.toBeNull()
    await expect(adapter.getSessionAndUser?.('tok-cascade')).resolves.toBeNull()
    await expect(adapter.listAuthenticatorsByUserId?.(user.id)).resolves.toEqual([])

    for (const slug of Object.values(defaultAuthJsSlugs)) {
      const remaining = await payload.find({ collection: slug, where: {}, limit: 100 })
      const leaked = remaining.docs.filter((doc: unknown) => {
        if (typeof doc !== 'object' || doc === null) {
          return false
        }
        const row = doc as Record<string, unknown>
        return row.auId === user.id || row.userId === user.id
      })
      expect(leaked).toEqual([])
    }

    // Idempotent: deleting twice is fine.
    await adapter.deleteUser?.(user.id)
  })
})

describe('error mapping', () => {
  function stubAdapter(
    findImpl: (args: { collection: string }) => Promise<{ docs: unknown[] }>
  ): Adapter {
    const stub = {
      find: vi.fn(findImpl),
      delete: vi.fn(() => Promise.resolve({ docs: [], errors: [] })),
    } as unknown as Payload
    return createAuthJsAdapter({ getPayload: () => Promise.resolve(stub) })
  }

  it('wraps storage outages as operation errors', async () => {
    const broken = stubAdapter(() => Promise.reject(new Error('db down')))
    await expect(broken.getUser?.('au-1')).rejects.toThrow(AdapterOperationError)
    await expect(broken.getSessionAndUser?.('tok-1')).rejects.toThrow(AdapterOperationError)
    await expect(broken.createUser?.(userInput('x@y.co'))).rejects.toThrow(AdapterOperationError)
  })

  it('throws mapping errors on corrupt documents, loudly', async () => {
    const corrupt = stubAdapter(() => Promise.resolve({ docs: [42] }))
    await expect(corrupt.getUser?.('au-1')).rejects.toThrow(AdapterMappingError)

    const noUserId = stubAdapter(({ collection }) =>
      Promise.resolve({
        docs: collection === defaultAuthJsSlugs.account ? [{ provider: 'github' }] : [],
      })
    )
    await expect(
      noUserId.getUserByAccount?.({ provider: 'github', providerAccountId: 'gh-1' })
    ).rejects.toThrow('account has no userId')

    const noId = stubAdapter(() => Promise.resolve({ docs: [{ auId: 'au-1' }] }))
    await expect(noId.deleteUser?.('au-1')).rejects.toThrow('document has no id')
  })

  it('rejects stored account types outside the Auth.js allowlist', async () => {
    const corrupt = stubAdapter(() =>
      Promise.resolve({
        docs: [
          {
            provider: 'github',
            providerAccountId: 'gh-1',
            userId: 'au-1',
            type: 'saml',
          },
        ],
      })
    )
    await expect(corrupt.getAccount?.('gh-1', 'github')).rejects.toThrow(AdapterMappingError)
    await expect(corrupt.getAccount?.('gh-1', 'github')).rejects.toThrow(
      'field type has unknown value "saml"'
    )
  })

  it('throws operation errors for updates on missing rows', async () => {
    const empty = stubAdapter(() => Promise.resolve({ docs: [] }))
    await expect(empty.updateUser?.({ id: 'ghost', email: 'g@g.co' })).rejects.toThrow(
      'updateUser on a missing user'
    )
    await expect(empty.updateAuthenticatorCounter?.('ghost', 1)).rejects.toThrow(
      'updateAuthenticatorCounter on a missing authenticator'
    )
  })
})
