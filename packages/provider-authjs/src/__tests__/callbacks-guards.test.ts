/**
 * Security guards in the Auth.js claims layer (issue #110): the D6
 * stamp never claims a verification the adapter did not store, and
 * the CAP-14 event translation never emits for unusable user rows or
 * without a lifecycle sink.
 */
import {
  createIdentityEventEmitter,
  nullLogger,
  type IdentityEvent,
  type LoggerPort,
} from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  createAuthLinkCallbacks,
  createAuthLinkEvents,
  emailVerifiedClaim,
  type AuthLinkCallbacks,
  type AuthLinkEvents,
} from '../callbacks.js'

type JwtParams = Parameters<AuthLinkCallbacks['jwt']>[0]
type UpdateUserMessage = Parameters<AuthLinkEvents['updateUser']>[0]
type LinkAccountMessage = Parameters<AuthLinkEvents['linkAccount']>[0]

function oauthJwtParams(): JwtParams {
  return {
    token: {},
    user: { id: 'au-1', email: 'a@b.co', emailVerified: null },
    account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
    profile: { email: 'a@b.co', email_verified: true },
    trigger: 'signIn',
  }
}

function recordingSink() {
  const emitter = createIdentityEventEmitter()
  const seen: IdentityEvent[] = []
  emitter.subscribe((event) => {
    seen.push(event)
    return Promise.resolve()
  })
  const warnings: string[] = []
  const logger: LoggerPort = {
    ...nullLogger(),
    warn: (message) => {
      warnings.push(message)
    },
  }
  return { lifecycle: { emitter, logger }, seen, warnings }
}

describe('D6 stamp trusts only the adapter-stored date', () => {
  it('claims nothing when updateUser does not return a verified date', async () => {
    // The adapter accepted the write but reports no verification
    // (e.g. a builder adapter that ignores the field): the token must
    // not claim one, and the shared user object is left unverified.
    const updateUser = vi.fn((user: { id: string }) =>
      Promise.resolve({ id: user.id, email: 'a@b.co', emailVerified: null })
    )
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const params = oauthJwtParams()
    const token = await jwt(params)
    expect(updateUser).toHaveBeenCalledTimes(1)
    expect(token?.[emailVerifiedClaim]).toBeNull()
    expect((params.user as { emailVerified?: unknown }).emailVerified).toBeNull()
  })

  it('a non-Date verification value from the adapter is not a stamp', async () => {
    const updateUser = vi.fn((user: { id: string }) =>
      Promise.resolve({
        id: user.id,
        email: 'a@b.co',
        emailVerified: '2026-01-01T00:00:00.000Z' as unknown as Date,
      })
    )
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    const token = await jwt(oauthJwtParams())
    expect(token?.[emailVerifiedClaim]).toBeNull()
  })

  it('an adapter failure propagates, never downgrading silently', async () => {
    const updateUser = vi.fn(() => Promise.reject(new Error('adapter down')))
    const { jwt } = createAuthLinkCallbacks(undefined, {
      trustProviderEmailVerification: ['google'],
      updateUser,
    })
    await expect(jwt(oauthJwtParams())).rejects.toThrow('adapter down')
  })
})

describe('CAP-14 event translation refuses unusable rows', () => {
  const unusable: readonly [string, unknown][] = [
    ['null', null],
    ['a non-object', 'au-1'],
    ['a missing id', { email: 'a@b.co', emailVerified: new Date() }],
    ['an empty id', { id: '', email: 'a@b.co', emailVerified: new Date() }],
    ['a non-string id', { id: 7, email: 'a@b.co', emailVerified: new Date() }],
    ['a missing email', { id: 'au-1', emailVerified: new Date() }],
    ['an invalid email', { id: 'au-1', email: 'not-an-email', emailVerified: new Date() }],
  ]

  for (const [label, user] of unusable) {
    it(`updateUser with ${label} is logged and skipped`, async () => {
      const sink = recordingSink()
      const events = createAuthLinkEvents(undefined, undefined, sink.lifecycle)
      await events.updateUser({ user } as unknown as UpdateUserMessage)
      expect(sink.seen).toEqual([])
      expect(sink.warnings).toEqual(['authjs updateUser event: unusable user row, event skipped'])
    })

    it(`linkAccount with ${label} emits nothing`, async () => {
      const sink = recordingSink()
      const events = createAuthLinkEvents(undefined, undefined, sink.lifecycle)
      await events.linkAccount({
        user,
        account: { provider: 'google', type: 'oidc', providerAccountId: 'g-1' },
        profile: { email: 'a@b.co' },
      } as unknown as LinkAccountMessage)
      expect(sink.seen).toEqual([])
    })
  }

  it('an unverified email change is emitted unverified (the applier ignores it)', async () => {
    const sink = recordingSink()
    const events = createAuthLinkEvents(undefined, undefined, sink.lifecycle)
    await events.updateUser({
      user: { id: 'au-2', email: 'NEW@Example.com', emailVerified: null },
    } as unknown as UpdateUserMessage)
    expect(sink.seen).toEqual([
      {
        type: 'email-changed',
        providerId: 'authjs',
        providerUserId: 'au-2',
        email: 'new@example.com',
        verified: false,
      },
    ])
  })

  it('without a lifecycle sink, builder events still run and nothing is emitted', async () => {
    const builderUpdate = vi.fn(() => Promise.resolve())
    const builderLink = vi.fn(() => Promise.resolve())
    const events = createAuthLinkEvents({ updateUser: builderUpdate, linkAccount: builderLink })
    const user = { id: 'au-3', email: 'a@b.co', emailVerified: new Date() }
    await events.updateUser({ user })
    await events.linkAccount({
      user,
      account: { provider: 'google', type: 'oidc', providerAccountId: 'g-3' },
      profile: { email: 'a@b.co' },
    } as unknown as LinkAccountMessage)
    expect(builderUpdate).toHaveBeenCalledTimes(1)
    expect(builderLink).toHaveBeenCalledTimes(1)
  })

  it('a builder event failure propagates before anything is emitted', async () => {
    const sink = recordingSink()
    const events = createAuthLinkEvents(
      { updateUser: () => Promise.reject(new Error('builder failed')) },
      undefined,
      sink.lifecycle
    )
    await expect(
      events.updateUser({
        user: { id: 'au-4', email: 'a@b.co', emailVerified: new Date() },
      } as unknown as UpdateUserMessage)
    ).rejects.toThrow('builder failed')
    expect(sink.seen).toEqual([])
  })
})
