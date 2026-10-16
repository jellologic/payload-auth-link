/**
 * Fail-closed edges of the server-side authorization helpers
 * (issue #86 coverage floors): actor parsing never launders a
 * malformed impersonation into a plain request, numeric Payload ids
 * are accepted, storage errors without a cause still log, and
 * `denyWithoutMfa` leaves undenied operations open.
 */
import { RepositoryError, type LoggerPort } from '@payload-auth-link/core'
import type { PayloadRequest } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import {
  denyWithoutMfa,
  impersonationActorFromRequest,
  impersonationStateFromRequest,
  logVerifyFailure,
} from '../access.js'

const reqWith = (actor: unknown): PayloadRequest =>
  ({ user: { id: 'u1', actor } }) as unknown as PayloadRequest

describe('impersonationStateFromRequest', () => {
  it.each([
    [{ providerUserId: 'p1' }, { kind: 'provider-only', providerUserId: 'p1' }],
    [
      { kind: 'provider-only', providerUserId: 'p2' },
      { kind: 'provider-only', providerUserId: 'p2' },
    ],
    [
      { kind: 'payload-user', providerUserId: 'p3', userId: 42 },
      { kind: 'payload-user', providerUserId: 'p3', userId: '42' },
    ],
    [
      { kind: 'payload-user', providerUserId: 'p4', userId: 'u-4' },
      { kind: 'payload-user', providerUserId: 'p4', userId: 'u-4' },
    ],
  ])('parses %j', (actor, expected) => {
    expect(impersonationActorFromRequest(reqWith(actor))).toEqual(expected)
  })

  it.each([
    [{}],
    [{ providerUserId: '' }],
    [{ kind: 'provider-only' }],
    [{ kind: 'payload-user', providerUserId: 'p', userId: Number.NaN }],
    [{ kind: 'payload-user', providerUserId: 'p', userId: '' }],
    [{ kind: 'payload-user', userId: 'u' }],
    [{ kind: 'someday-kind', providerUserId: 'p' }],
    ['not-a-record'],
  ])('a present but malformed actor %j is malformed-actor (fail closed)', (actor) => {
    expect(impersonationStateFromRequest(reqWith(actor))).toEqual({ kind: 'malformed-actor' })
    expect(impersonationActorFromRequest(reqWith(actor))).toBeNull()
  })

  it('no user or no actor is none', () => {
    expect(impersonationStateFromRequest({ user: null } as unknown as PayloadRequest)).toEqual({
      kind: 'none',
    })
    expect(impersonationStateFromRequest(reqWith(null))).toEqual({ kind: 'none' })
  })
})

describe('logVerifyFailure', () => {
  it('logs a storage error without a cause using the error itself', () => {
    const error = vi.fn()
    const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error } as unknown as LoggerPort
    const failure = new RepositoryError('findById')
    logVerifyFailure(logger, 'strategy', failure)
    expect(error).toHaveBeenCalledWith('strategy verification failed: storage error', {
      cause: failure,
    })
  })
})

describe('denyWithoutMfa', () => {
  it('leaves undenied operations open, including admin', () => {
    const access = denyWithoutMfa(['update'])
    const req = { user: { id: 'u1' } } as unknown as PayloadRequest
    // v4 types access fns with the collection `slug`; a non-literal
    // keeps v3's narrower arg type satisfied too.
    const args = { req, slug: 'users' }
    expect(access.admin?.(args)).toBe(true)
    expect(access.read?.({ req } as never)).toBe(true)
    expect(access.update?.({ req } as never)).toBe(false)
  })
})
