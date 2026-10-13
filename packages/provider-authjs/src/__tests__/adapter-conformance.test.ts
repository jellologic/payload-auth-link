/**
 * Adapter conformance: our maintained equivalent of the upstream Auth.js
 * adapter test suite (`runBasicTests`, next-auth
 * `packages/utils/adapter.ts`, referenced from `@auth/core/adapters`).
 * The upstream suite is monorepo-internal and cannot be a dependency
 * (docs/PLAN-CAPABILITIES.md spike S7), so this file re-implements the
 * same 22 behaviors as our own assertions against real Payload storage
 * (SQLite in memory), including the WebAuthn authenticator methods that
 * upstream gates behind `testWebAuthnMethods`. No upstream code is
 * copied; test names state the behavior being pinned.
 *
 * Behavior inventory (upstream case -> here):
 * users: create, get by id, get by email, get by account, update,
 * delete (plus null-on-missing reads); accounts: link, get, unlink;
 * sessions: create, get session+user, update, delete; verification
 * tokens: create, use (single-use); authenticators: create, get, list
 * by user, update counter. Three extra cases pin composite
 * (identifier, token) uniqueness (spikes S2/S7, prerequisite for CAP-2
 * email OTP, where different identifiers can receive the same 6-digit
 * code and therefore the same token hash).
 */
import type {
  Adapter,
  AdapterAccount,
  AdapterAuthenticator,
  AdapterUser,
} from '@auth/core/adapters'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { beforeAll, describe, expect, expectTypeOf, it } from 'vitest'
import { createAuthJsAdapter } from '../adapter.js'
import { createAuthJsCollections } from '../collections.js'
import { AdapterOperationError } from '../errors.js'

const SECRET = 'authjs-adapter-conformance-secret!!'
const FUTURE = new Date('2027-01-01T00:00:00.000Z')
const LATER = new Date('2027-06-01T00:00:00.000Z')

type AdapterMethod = keyof Adapter
const REQUIRED_METHODS = [
  'createUser',
  'getUser',
  'getUserByEmail',
  'getUserByAccount',
  'updateUser',
  'deleteUser',
  'linkAccount',
  'unlinkAccount',
  'getAccount',
  'createSession',
  'getSessionAndUser',
  'updateSession',
  'deleteSession',
  'createVerificationToken',
  'useVerificationToken',
  'createAuthenticator',
  'getAuthenticator',
  'listAuthenticatorsByUserId',
  'updateAuthenticatorCounter',
] as const satisfies readonly AdapterMethod[]

describe('Adapter inventory alarm (B22)', () => {
  it('pins keyof Adapter: a new upstream method fails typecheck here', () => {
    // Every `Adapter` method in @auth/core is optional, so an
    // upstream addition (the `consumeOne` class of break) typechecks
    // silently everywhere except this pin. If this fails after an
    // @auth/core bump: implement the new method (or consciously
    // leave it unimplemented and document why), extend
    // REQUIRED_METHODS + its conformance case, then update the pin.
    expectTypeOf<keyof Adapter>().toEqualTypeOf<
      | 'createUser'
      | 'getUser'
      | 'getUserByEmail'
      | 'getUserByAccount'
      | 'updateUser'
      | 'deleteUser'
      | 'linkAccount'
      | 'unlinkAccount'
      | 'getAccount'
      | 'createSession'
      | 'getSessionAndUser'
      | 'updateSession'
      | 'deleteSession'
      | 'createVerificationToken'
      | 'useVerificationToken'
      | 'createAuthenticator'
      | 'getAuthenticator'
      | 'listAuthenticatorsByUserId'
      | 'updateAuthenticatorCounter'
    >()
    expectTypeOf<(typeof REQUIRED_METHODS)[number]>().toEqualTypeOf<keyof Adapter>()
    expect(REQUIRED_METHODS).toHaveLength(19)
  })
})

let payload: Payload
let adapter: Adapter
let sequence = 0

function unique(prefix: string): string {
  sequence += 1
  return `${prefix}-${sequence}`
}

function method<K extends AdapterMethod>(name: K): NonNullable<Adapter[K]> {
  const fn = adapter[name]
  if (fn === undefined) {
    throw new Error(`adapter method ${name} is not implemented`)
  }
  return fn.bind(adapter) as NonNullable<Adapter[K]>
}

async function makeUser(overrides: Partial<AdapterUser> = {}): Promise<AdapterUser> {
  const created = await method('createUser')({
    id: '',
    email: `${unique('user')}@example.com`,
    emailVerified: null,
    ...overrides,
  })
  if (created === null || created === undefined) {
    throw new Error('createUser returned nothing')
  }
  return created
}

function accountFor(userId: string, overrides: Partial<AdapterAccount> = {}): AdapterAccount {
  return {
    provider: 'github',
    providerAccountId: unique('gh'),
    userId,
    type: 'oauth',
    access_token: 'at-1',
    refresh_token: 'rt-1',
    scope: 'read:user',
    expires_at: Math.floor(FUTURE.getTime() / 1000),
    ...overrides,
  }
}

function authenticatorFor(
  userId: string,
  overrides: Partial<AdapterAuthenticator> = {}
): AdapterAuthenticator {
  return {
    credentialID: unique('cred'),
    userId,
    providerAccountId: unique('pa'),
    credentialPublicKey: 'pubkey',
    counter: 0,
    credentialBackedUp: false,
    credentialDeviceType: 'singleDevice',
    transports: 'usb,nfc',
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
  for (const name of REQUIRED_METHODS) {
    expect(typeof adapter[name], `adapter implements ${name}`).toBe('function')
  }
})

describe('conformance: users', () => {
  it('createUser returns the stored user with a generated id', async () => {
    const user = await makeUser({ name: 'Conf', image: 'https://example.com/a.png' })
    expect(user.id).not.toBe('')
    expect(user).toMatchObject({ name: 'Conf', image: 'https://example.com/a.png' })
    expect(user.emailVerified).toBeNull()
  })

  it('createUser honors a builder-provided id and verified date', async () => {
    const id = unique('au')
    const user = await makeUser({ id, emailVerified: FUTURE })
    expect(user.id).toBe(id)
    expect(user.emailVerified).toEqual(FUTURE)
  })

  it('getUser returns the user by id and null when missing', async () => {
    const user = await makeUser()
    await expect(method('getUser')(user.id)).resolves.toMatchObject({ email: user.email })
    await expect(method('getUser')(unique('missing'))).resolves.toBeNull()
  })

  it('getUserByEmail returns the user and null when missing', async () => {
    const user = await makeUser()
    await expect(method('getUserByEmail')(user.email)).resolves.toMatchObject({ id: user.id })
    await expect(method('getUserByEmail')(`${unique('no')}@example.com`)).resolves.toBeNull()
  })

  it('updateUser patches profile fields and email verification', async () => {
    const user = await makeUser()
    const updated = await method('updateUser')({
      id: user.id,
      email: user.email,
      name: 'Renamed',
      emailVerified: FUTURE,
    })
    expect(updated).toMatchObject({ name: 'Renamed', emailVerified: FUTURE })
    await expect(method('getUser')(user.id)).resolves.toMatchObject({ name: 'Renamed' })
    const cleared = await method('updateUser')({
      id: user.id,
      email: user.email,
      emailVerified: null,
    })
    expect(cleared.emailVerified).toBeNull()
  })

  it('deleteUser removes the user and is idempotent', async () => {
    const user = await makeUser()
    await method('deleteUser')(user.id)
    await expect(method('getUser')(user.id)).resolves.toBeNull()
    await method('deleteUser')(user.id)
  })

  it('deleteUser cascades accounts, sessions, and authenticators', async () => {
    const user = await makeUser()
    const account = accountFor(user.id)
    await method('linkAccount')(account)
    const sessionToken = unique('tok')
    await method('createSession')({ sessionToken, userId: user.id, expires: FUTURE })
    await method('createAuthenticator')(authenticatorFor(user.id))

    await method('deleteUser')(user.id)

    await expect(
      method('getAccount')(account.providerAccountId, account.provider)
    ).resolves.toBeNull()
    await expect(method('getSessionAndUser')(sessionToken)).resolves.toBeNull()
    await expect(method('listAuthenticatorsByUserId')(user.id)).resolves.toEqual([])
  })
})

describe('conformance: accounts', () => {
  it('linkAccount stores and returns the account', async () => {
    const user = await makeUser()
    const account = accountFor(user.id)
    const linked = await method('linkAccount')(account)
    expect(linked).toMatchObject({
      provider: account.provider,
      providerAccountId: account.providerAccountId,
      userId: user.id,
      type: 'oauth',
      access_token: 'at-1',
    })
  })

  it('getAccount returns the account by provider pair and null when missing', async () => {
    const user = await makeUser()
    const account = accountFor(user.id)
    await method('linkAccount')(account)
    await expect(
      method('getAccount')(account.providerAccountId, account.provider)
    ).resolves.toMatchObject({ userId: user.id })
    await expect(method('getAccount')(account.providerAccountId, 'gitlab')).resolves.toBeNull()
    await expect(method('getAccount')(unique('nope'), account.provider)).resolves.toBeNull()
  })

  it('getUserByAccount resolves the linked user and null when missing', async () => {
    const user = await makeUser()
    const account = accountFor(user.id)
    await method('linkAccount')(account)
    await expect(
      method('getUserByAccount')({
        provider: account.provider,
        providerAccountId: account.providerAccountId,
      })
    ).resolves.toMatchObject({ id: user.id })
    await expect(
      method('getUserByAccount')({ provider: account.provider, providerAccountId: 'nope' })
    ).resolves.toBeNull()
  })

  it('unlinkAccount removes the account and is idempotent', async () => {
    const user = await makeUser()
    const account = accountFor(user.id)
    await method('linkAccount')(account)
    const ref = { provider: account.provider, providerAccountId: account.providerAccountId }
    await method('unlinkAccount')(ref)
    await expect(method('getAccount')(ref.providerAccountId, ref.provider)).resolves.toBeNull()
    await expect(method('getUserByAccount')(ref)).resolves.toBeNull()
    await method('unlinkAccount')(ref)
  })
})

describe('conformance: sessions', () => {
  it('createSession stores and returns the session', async () => {
    const user = await makeUser()
    const sessionToken = unique('tok')
    const session = await method('createSession')({
      sessionToken,
      userId: user.id,
      expires: FUTURE,
    })
    expect(session).toMatchObject({ sessionToken, userId: user.id, expires: FUTURE })
  })

  it('getSessionAndUser joins session to user and is null when missing', async () => {
    const user = await makeUser()
    const sessionToken = unique('tok')
    await method('createSession')({ sessionToken, userId: user.id, expires: FUTURE })
    const joined = await method('getSessionAndUser')(sessionToken)
    expect(joined?.session.sessionToken).toBe(sessionToken)
    expect(joined?.user.id).toBe(user.id)
    await expect(method('getSessionAndUser')(unique('missing'))).resolves.toBeNull()
  })

  it('getSessionAndUser is null when the session user is gone', async () => {
    const sessionToken = unique('tok')
    await method('createSession')({ sessionToken, userId: unique('ghost'), expires: FUTURE })
    await expect(method('getSessionAndUser')(sessionToken)).resolves.toBeNull()
  })

  it('updateSession extends expiry and returns null when missing', async () => {
    const user = await makeUser()
    const sessionToken = unique('tok')
    await method('createSession')({ sessionToken, userId: user.id, expires: FUTURE })
    const updated = await method('updateSession')({ sessionToken, expires: LATER })
    expect(updated?.expires).toEqual(LATER)
    await expect(
      method('updateSession')({ sessionToken: unique('missing'), expires: LATER })
    ).resolves.toBeNull()
  })

  it('deleteSession removes the session and is idempotent', async () => {
    const user = await makeUser()
    const sessionToken = unique('tok')
    await method('createSession')({ sessionToken, userId: user.id, expires: FUTURE })
    await method('deleteSession')(sessionToken)
    await expect(method('getSessionAndUser')(sessionToken)).resolves.toBeNull()
    await method('deleteSession')(sessionToken)
  })
})

describe('conformance: verification tokens', () => {
  it('createVerificationToken stores and returns the token', async () => {
    const token = {
      identifier: `${unique('vt')}@example.com`,
      token: unique('hash'),
      expires: FUTURE,
    }
    await expect(method('createVerificationToken')(token)).resolves.toMatchObject(token)
  })

  it('useVerificationToken returns the token once, then it is gone', async () => {
    const token = {
      identifier: `${unique('vt')}@example.com`,
      token: unique('hash'),
      expires: FUTURE,
    }
    await method('createVerificationToken')(token)
    await expect(
      method('useVerificationToken')({ identifier: token.identifier, token: token.token })
    ).resolves.toMatchObject(token)
    await expect(
      method('useVerificationToken')({ identifier: token.identifier, token: token.token })
    ).resolves.toBeNull()
  })

  it('useVerificationToken is null for a wrong token or identifier and consumes nothing', async () => {
    const token = {
      identifier: `${unique('vt')}@example.com`,
      token: unique('hash'),
      expires: FUTURE,
    }
    await method('createVerificationToken')(token)
    await expect(
      method('useVerificationToken')({ identifier: token.identifier, token: 'wrong' })
    ).resolves.toBeNull()
    await expect(
      method('useVerificationToken')({ identifier: 'other@example.com', token: token.token })
    ).resolves.toBeNull()
    // A failed guess must not consume the real token (OTP brute-force note, S2).
    await expect(
      method('useVerificationToken')({ identifier: token.identifier, token: token.token })
    ).resolves.toMatchObject(token)
  })

  it('allows the same token hash for different identifiers (duplicate OTP codes)', async () => {
    const sharedHash = unique('shared-hash')
    const first = {
      identifier: `${unique('otp-a')}@example.com`,
      token: sharedHash,
      expires: FUTURE,
    }
    const second = {
      identifier: `${unique('otp-b')}@example.com`,
      token: sharedHash,
      expires: LATER,
    }
    await expect(method('createVerificationToken')(first)).resolves.toMatchObject(first)
    await expect(method('createVerificationToken')(second)).resolves.toMatchObject(second)
  })

  it('consuming one identifier token does not affect another with the same hash', async () => {
    const sharedHash = unique('shared-hash')
    const first = {
      identifier: `${unique('otp-a')}@example.com`,
      token: sharedHash,
      expires: FUTURE,
    }
    const second = {
      identifier: `${unique('otp-b')}@example.com`,
      token: sharedHash,
      expires: LATER,
    }
    await method('createVerificationToken')(first)
    await method('createVerificationToken')(second)

    await expect(
      method('useVerificationToken')({ identifier: first.identifier, token: sharedHash })
    ).resolves.toMatchObject(first)
    await expect(
      method('useVerificationToken')({ identifier: second.identifier, token: sharedHash })
    ).resolves.toMatchObject(second)
    await expect(
      method('useVerificationToken')({ identifier: second.identifier, token: sharedHash })
    ).resolves.toBeNull()
  })

  it('rejects a duplicate (identifier, token) pair without replacing the original', async () => {
    // Upstream reference adapters key verification tokens by the composite
    // (identifier, token) pair, so re-creating the same pair fails rather
    // than silently extending/replacing the live token.
    const token = {
      identifier: `${unique('vt')}@example.com`,
      token: unique('hash'),
      expires: FUTURE,
    }
    await method('createVerificationToken')(token)
    await expect(method('createVerificationToken')({ ...token, expires: LATER })).rejects.toThrow(
      AdapterOperationError
    )
    const claimed = await method('useVerificationToken')({
      identifier: token.identifier,
      token: token.token,
    })
    expect(claimed?.expires).toEqual(FUTURE)
  })
})

describe('conformance: authenticators (WebAuthn)', () => {
  it('createAuthenticator stores and getAuthenticator returns it', async () => {
    const user = await makeUser()
    const authenticator = authenticatorFor(user.id)
    await expect(method('createAuthenticator')(authenticator)).resolves.toMatchObject({
      credentialID: authenticator.credentialID,
      userId: user.id,
      counter: 0,
      transports: 'usb,nfc',
    })
    await expect(method('getAuthenticator')(authenticator.credentialID)).resolves.toMatchObject({
      credentialPublicKey: 'pubkey',
      credentialDeviceType: 'singleDevice',
    })
  })

  it('getAuthenticator is null when missing', async () => {
    await expect(method('getAuthenticator')(unique('missing'))).resolves.toBeNull()
  })

  it('listAuthenticatorsByUserId lists only that user authenticators', async () => {
    const user = await makeUser()
    const other = await makeUser()
    const first = authenticatorFor(user.id)
    const second = authenticatorFor(user.id)
    await method('createAuthenticator')(first)
    await method('createAuthenticator')(second)
    await method('createAuthenticator')(authenticatorFor(other.id))
    const listed = await method('listAuthenticatorsByUserId')(user.id)
    expect(listed.map((entry) => entry.credentialID).sort()).toEqual(
      [first.credentialID, second.credentialID].sort()
    )
    await expect(method('listAuthenticatorsByUserId')(unique('ghost'))).resolves.toEqual([])
  })

  it('updateAuthenticatorCounter persists the new counter', async () => {
    const user = await makeUser()
    const authenticator = authenticatorFor(user.id)
    await method('createAuthenticator')(authenticator)
    const bumped = await method('updateAuthenticatorCounter')(authenticator.credentialID, 9)
    expect(bumped.counter).toBe(9)
    await expect(method('getAuthenticator')(authenticator.credentialID)).resolves.toMatchObject({
      counter: 9,
    })
  })
})
