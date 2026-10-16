/**
 * `verifyApiKey` response narrowing (issue #110, port.ts
 * `narrowApiKeyVerification`): the OWNER of a verified key decides
 * which Payload user a key resolves to, so every shape that does not
 * name exactly one owner must fail closed — never resolve to an empty
 * or non-string owner, never treat an invalid verification as valid.
 *
 * Driven through both port constructors with scripted
 * `@better-auth/api-key` responses (the real-engine paths live in
 * `api-key-verify.test.ts` and `channel-api-key-engine.test.ts`).
 */
import { ProviderError, type IdentityProviderPort } from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import { createBetterAuthProvider, createBetterAuthProviderFromUnknown } from '../port.js'

const cookieNames = ['better-auth.session_token']
const context = { internalAdapter: { deleteSession: () => Promise.resolve() } }

function ports(response: unknown): readonly IdentityProviderPort[] {
  const verifyApiKey = () => Promise.resolve(response)
  return [
    createBetterAuthProvider({
      auth: {
        api: { getSession: () => Promise.resolve(null) },
        $context: Promise.resolve(context),
        verifyApiKey,
      },
      sessionCookieNames: cookieNames,
    }),
    createBetterAuthProviderFromUnknown(
      {
        api: { getSession: () => Promise.resolve(null), verifyApiKey },
        $context: Promise.resolve(context),
      },
      cookieNames
    ),
  ]
}

async function verifyAll(response: unknown) {
  return Promise.all(
    ports(response).map(async (port) => {
      const verify = port.verifyApiKey
      if (verify === undefined) {
        throw new Error('port exposes no verifyApiKey')
      }
      return verify('pal_key')
    })
  )
}

describe('verifyApiKey owner narrowing', () => {
  it('a 1.7.x key resolves to its referenceId owner, which wins over userId', async () => {
    for (const result of await verifyAll({
      valid: true,
      key: { referenceId: 'ba-owner', userId: 'ba-legacy', name: 'ci' },
    })) {
      expect(result.isOk() && result.value?.userId).toBe('ba-owner')
    }
  })

  it('a 1.6-era key falls back to userId only when referenceId is absent or empty', async () => {
    for (const key of [{ userId: 'ba-legacy' }, { referenceId: '', userId: 'ba-legacy' }]) {
      for (const result of await verifyAll({ valid: true, key })) {
        expect(result.isOk() && result.value?.userId).toBe('ba-legacy')
      }
    }
  })

  it.each([
    ['no owner field', {}],
    ['empty owners', { referenceId: '', userId: '' }],
    ['non-string owners', { referenceId: 42, userId: { id: 'ba-x' } }],
  ])('a valid verification with %s fails closed with a ProviderError', async (_label, key) => {
    for (const result of await verifyAll({ valid: true, key })) {
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(ProviderError)
      }
    }
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['false', false],
    ['valid: false', { valid: false, key: { referenceId: 'ba-owner' } }],
    ['valid: "true" (not strictly true)', { valid: 'true', key: { referenceId: 'ba-owner' } }],
    ['a missing key block', { valid: true }],
    ['a non-record key block', { valid: true, key: 'ba-owner' }],
    ['an error envelope', { valid: false, error: { code: 'KEY_DISABLED' }, key: null }],
  ])('%s narrows to null (no owner, no key)', async (_label, response) => {
    for (const result of await verifyAll(response)) {
      expect(result.isOk() && result.value).toBeNull()
    }
  })
})

describe('verifyApiKey key metadata narrowing', () => {
  it('carries well-typed fields and nulls the rest', async () => {
    const expiresAt = '2027-01-01T00:00:00.000Z'
    for (const result of await verifyAll({
      valid: true,
      key: {
        referenceId: 'ba-owner',
        name: 'deploy',
        start: 'pal_ab',
        prefix: 'pal_',
        metadata: { team: 'ops' },
        rateLimitEnabled: true,
        remaining: '7',
        expiresAt,
        permissions: '{"files":["read"]}',
      },
    })) {
      expect(result.isOk() && result.value).toEqual({
        userId: 'ba-owner',
        name: 'deploy',
        start: 'pal_ab',
        prefix: 'pal_',
        metadata: { team: 'ops' },
        rateLimitEnabled: true,
        rateLimitRemaining: 7,
        expiresAt: new Date(expiresAt),
        permissions: '{"files":["read"]}',
      })
    }
  })

  it('a numeric remaining count and a Date expiry pass through', async () => {
    const expiresAt = new Date('2027-02-02T00:00:00.000Z')
    for (const result of await verifyAll({
      valid: true,
      key: { referenceId: 'ba-owner', remaining: 3, expiresAt },
    })) {
      expect(result.isOk() && result.value?.rateLimitRemaining).toBe(3)
      expect(result.isOk() && result.value?.expiresAt).toEqual(expiresAt)
    }
  })

  it('mistyped metadata fields narrow to null, never to a coerced value', async () => {
    for (const result of await verifyAll({
      valid: true,
      key: {
        referenceId: 'ba-owner',
        name: 7,
        start: null,
        prefix: {},
        rateLimitEnabled: 'yes',
        remaining: '',
        expiresAt: 1234,
        permissions: ['read'],
      },
    })) {
      expect(result.isOk() && result.value).toEqual({
        userId: 'ba-owner',
        name: null,
        start: null,
        prefix: null,
        metadata: null,
        rateLimitEnabled: null,
        rateLimitRemaining: null,
        expiresAt: null,
        permissions: null,
      })
    }
  })

  it('a throwing verifier fails the operation, never resolves an owner', async () => {
    const throwing = createBetterAuthProviderFromUnknown(
      {
        api: {
          getSession: () => Promise.resolve(null),
          verifyApiKey: () => Promise.reject(new Error('store down')),
        },
        $context: Promise.resolve(context),
      },
      cookieNames
    )
    const result = await throwing.verifyApiKey?.('pal_key')
    expect(result?.isErr()).toBe(true)
  })
})
