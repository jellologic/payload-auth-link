/**
 * Better Auth port fail-closed narrowing and revocation verification
 * (issue #86):
 *
 * - a session whose user carries a NON-boolean `emailVerified` is
 *   malformed and refused — a truthy string or number read as
 *   "verified" would hand an unverified address linking authority
 *   (SEC-2);
 * - a revocation is verified AFTER the delete: if the session row is
 *   still there, the revoke is an error, never a silent success.
 *
 * Both port constructors (`createBetterAuthProvider` and
 * `createBetterAuthProviderFromUnknown`) are pinned.
 */
import { ProviderError } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  createBetterAuthProvider,
  createBetterAuthProviderFromUnknown,
  type BetterAuthServerApi,
} from '../port.js'

const cookieNames = ['better-auth.session_token']
const headers = new Headers({ cookie: 'better-auth.session_token=tok' })

function messages(error: unknown): string {
  const parts: string[] = []
  let current: unknown = error
  while (current instanceof Error) {
    parts.push(current.message)
    current = current.cause
  }
  return parts.join(' <- ')
}

function typed(result: unknown, context: unknown): BetterAuthServerApi {
  return {
    api: { getSession: () => Promise.resolve(result) },
    $context: Promise.resolve(context),
  } as BetterAuthServerApi
}

describe('emailVerified narrowing', () => {
  it.each([['true'], [1], [0], [null], [undefined], [{}]])(
    'refuses emailVerified=%j with a ProviderError (both constructors)',
    async (emailVerified) => {
      const session = {
        session: { token: 'tok-1', expiresAt: new Date(Date.now() + 60_000) },
        user: { id: 'ba-1', email: 'user@example.com', emailVerified },
      }
      const context = { internalAdapter: { deleteSession: () => Promise.resolve() } }
      for (const provider of [
        createBetterAuthProvider({
          auth: typed(session, context),
          sessionCookieNames: cookieNames,
        }),
        createBetterAuthProviderFromUnknown(
          {
            api: { getSession: () => Promise.resolve(session) },
            $context: Promise.resolve(context),
          },
          cookieNames
        ),
      ]) {
        const result = await provider.getSession(headers)
        expect(result.isErr()).toBe(true)
        if (result.isErr()) {
          expect(result.error).toBeInstanceOf(ProviderError)
          expect(messages(result.error)).toMatch(/emailVerified flag is missing/)
        }
      }
    }
  )
})

describe('revokeSession post-delete verification (createBetterAuthProvider)', () => {
  it('errors when the session row survives the delete', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    // Present before AND after: the delete did nothing.
    const findSessions = vi.fn().mockResolvedValue([{ session: { token: 'tok-1' } }])
    const findOne = vi.fn().mockResolvedValue({ id: 'sess-1', token: 'tok-1' })
    const provider = createBetterAuthProvider({
      auth: typed(null, { internalAdapter: { deleteSession, findSessions }, adapter: { findOne } }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.revokeSession('sess-1')
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(messages(result.error)).toMatch(/no session was deleted for the given id/)
    }
    // The opaque id was resolved to the token server-side.
    expect(findOne).toHaveBeenCalledWith({
      model: 'session',
      where: [{ field: 'id', value: 'sess-1' }],
    })
    expect(deleteSession).toHaveBeenCalledWith('tok-1')
  })

  it('errors when deletion cannot be verified (no findSessions)', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const provider = createBetterAuthProvider({
      auth: typed(null, { internalAdapter: { deleteSession } }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.revokeSession('tok-1')
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(messages(result.error)).toMatch(/deletion cannot be verified/)
    }
    expect(deleteSession).not.toHaveBeenCalled()
  })

  it('errors for an unknown handle without deleting anything', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const findSessions = vi.fn().mockResolvedValue([])
    const findOne = vi.fn().mockResolvedValue(null)
    const provider = createBetterAuthProvider({
      auth: typed(null, { internalAdapter: { deleteSession, findSessions }, adapter: { findOne } }),
      sessionCookieNames: cookieNames,
    })
    const result = await provider.revokeSession('ghost')
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(messages(result.error)).toMatch(/no session exists for the given id/)
    }
    expect(deleteSession).not.toHaveBeenCalled()
  })
})

describe('revokeSession post-delete verification (createBetterAuthProviderFromUnknown)', () => {
  function provider(context: unknown) {
    return createBetterAuthProviderFromUnknown(
      { api: { getSession: () => Promise.resolve(null) }, $context: Promise.resolve(context) },
      cookieNames
    )
  }

  it('errors when the session row survives the delete', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const findSessions = vi.fn().mockResolvedValue([{ session: { token: 'tok-1' } }])
    const findOne = vi.fn().mockResolvedValue({ id: 'sess-1', token: 'tok-1' })
    const result = await provider({
      internalAdapter: { deleteSession, findSessions },
      adapter: { findOne },
    }).revokeSession('sess-1')
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(messages(result.error)).toMatch(/no session was deleted for the given id/)
    }
    expect(deleteSession).toHaveBeenCalledWith('tok-1')
    expect(findSessions).toHaveBeenCalledWith(['tok-1'])
  })

  it('succeeds once the row is verifiably gone', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const findSessions = vi.fn().mockResolvedValue([])
    const findOne = vi.fn().mockResolvedValue({ id: 'sess-1', token: 'tok-1' })
    const result = await provider({
      internalAdapter: { deleteSession, findSessions },
      adapter: { findOne },
    }).revokeSession('sess-1')
    expect(result.isOk()).toBe(true)
  })

  it('errors for an unknown handle when an adapter can resolve ids', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const result = await provider({
      internalAdapter: { deleteSession, findSessions: vi.fn().mockResolvedValue([]) },
      adapter: { findOne: vi.fn().mockResolvedValue(null) },
    }).revokeSession('ghost')
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(messages(result.error)).toMatch(/no session exists for the given id/)
    }
    expect(deleteSession).not.toHaveBeenCalled()
  })

  it('without an adapter, treats the handle as the token and still verifies', async () => {
    const deleteSession = vi.fn().mockResolvedValue(undefined)
    const findSessions = vi.fn().mockResolvedValue([{ session: { token: 'raw-token' } }])
    const result = await provider({
      internalAdapter: { deleteSession, findSessions },
    }).revokeSession('raw-token')
    expect(deleteSession).toHaveBeenCalledWith('raw-token')
    expect(result.isErr()).toBe(true)
  })
})

describe('createProviderSession records the minted method (createBetterAuthProvider)', () => {
  it.each([
    [true, 'server-step-up'],
    [false, 'server-mint'],
    [undefined, 'server-mint'],
  ] as const)('mfaProof=%s writes authenticationMethod %s', async (mfaProof, method) => {
    const expiresAt = new Date(Date.now() + 60_000)
    const createSession = vi
      .fn()
      .mockResolvedValue({ id: 'sess-1', token: 'tok-1', expiresAt: expiresAt.toISOString() })
    const provider = createBetterAuthProvider({
      auth: typed(null, { internalAdapter: { createSession } }),
      sessionCookieNames: cookieNames,
    })
    const created = await provider.createProviderSession?.('ba-1', {
      expiresAt,
      ...(mfaProof === undefined ? {} : { mfaProof }),
    })
    expect(created?.isOk()).toBe(true)
    expect(createSession).toHaveBeenCalledWith(
      'ba-1',
      false,
      { expiresAt, authenticationMethod: method },
      true
    )
  })
})
