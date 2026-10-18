/**
 * The CAP-14 lifecycle bus (`events.ts`): BA `databaseHooks` rows
 * arrive as `unknown` and become core `IdentityEvent`s. It feeds the
 * plugin's verified-email sync, so every narrowing branch is pinned:
 * a row that cannot be narrowed is skipped with a logged warning —
 * never thrown into the provider operation that already committed,
 * and never emitted half-formed.
 */
import { nullLogger, type IdentityEvent, type LoggerPort } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import { createIdentityEventBus } from '../events.js'

function setup() {
  const warn = vi.fn()
  const logger: LoggerPort = { ...nullLogger(), warn }
  const bus = createIdentityEventBus(logger)
  const events: IdentityEvent[] = []
  const unsubscribe = bus.subscribe((event) => {
    events.push(event)
    return Promise.resolve()
  })
  return { bus, events, warn, unsubscribe }
}

describe('createIdentityEventBus (CAP-14)', () => {
  it('user update → email-changed carrying the verification state', async () => {
    const { bus, events, warn } = setup()
    await bus.userUpdated({ id: 'u1', email: 'a@example.com', emailVerified: true })
    await bus.userUpdated({ id: 'u1', email: 'b@example.com', emailVerified: false })
    // A missing / non-boolean flag is NOT verified.
    await bus.userUpdated({ id: 'u1', email: 'c@example.com', emailVerified: 'yes' })
    expect(events).toEqual([
      {
        type: 'email-changed',
        providerId: 'better-auth',
        providerUserId: 'u1',
        email: 'a@example.com',
        verified: true,
      },
      {
        type: 'email-changed',
        providerId: 'better-auth',
        providerUserId: 'u1',
        email: 'b@example.com',
        verified: false,
      },
      {
        type: 'email-changed',
        providerId: 'better-auth',
        providerUserId: 'u1',
        email: 'c@example.com',
        verified: false,
      },
    ])
    expect(warn).not.toHaveBeenCalled()
  })

  it.each([
    ['a non-record', null],
    ['a missing id', { email: 'a@example.com' }],
    ['an empty id', { id: '', email: 'a@example.com' }],
    ['a missing email', { id: 'u1' }],
    ['an empty email', { id: 'u1', email: '' }],
  ])('user update with %s is skipped and logged', async (_label, row) => {
    const { bus, events, warn } = setup()
    await bus.userUpdated(row)
    expect(events).toEqual([])
    expect(warn).toHaveBeenCalledWith(
      'better-auth user.update hook: unusable user row, event skipped'
    )
  })

  it('user update with an unparseable email is skipped and logged with the user id', async () => {
    const { bus, events, warn } = setup()
    await bus.userUpdated({ id: 'u1', email: 'not-an-email', emailVerified: true })
    expect(events).toEqual([])
    expect(warn).toHaveBeenCalledWith(
      'better-auth user.update hook: unparseable email, event skipped',
      { providerUserId: 'u1' }
    )
  })

  it('user delete → user-deleted; an unusable row is skipped and logged', async () => {
    const { bus, events, warn } = setup()
    await bus.userDeleted({ id: 'u2', email: 'gone@example.com' })
    await bus.userDeleted({ id: 'u3' })
    expect(events).toEqual([
      { type: 'user-deleted', providerId: 'better-auth', providerUserId: 'u2' },
    ])
    expect(warn).toHaveBeenCalledWith(
      'better-auth user.delete hook: unusable user row, event skipped'
    )
  })

  it.each([
    ['a non-record', 'row'],
    ['a missing userId', { id: 'a1' }],
    ['an empty userId', { id: 'a1', userId: '' }],
    ['a non-string userId', { id: 'a1', userId: 7 }],
  ])('account delete with %s is skipped and logged', async (_label, row) => {
    const { bus, events, warn } = setup()
    await bus.accountDeleted(row)
    expect(events).toEqual([])
    expect(warn).toHaveBeenCalledWith(
      'better-auth account.delete hook: unusable account row, event skipped'
    )
  })

  it('account delete → identity-unlinked for the owning user', async () => {
    const { bus, events } = setup()
    await bus.accountDeleted({ id: 'a1', userId: 'u4', providerId: 'github' })
    expect(events).toEqual([
      { type: 'identity-unlinked', providerId: 'better-auth', providerUserId: 'u4' },
    ])
  })

  it('unsubscribing stops delivery', async () => {
    const { bus, events, unsubscribe } = setup()
    unsubscribe()
    await bus.userDeleted({ id: 'u5', email: 'x@example.com' })
    expect(events).toEqual([])
  })
})
