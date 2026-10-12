import { ProviderError } from '@payload-auth-link/core'
import { describe, expect, it, vi, type Mock } from 'vitest'
import { createAuthJsProvider, type AuthJsSessionApi } from '../port.js'

const cookieNames = ['authjs.session-token', 'authjs.session-token.0', 'authjs.session-token.1']

type ReadMock = Mock<(headers: Headers) => Promise<unknown>>
type RevokeMock = Mock<(sessionId: string) => Promise<unknown>>
type StubSessions = AuthJsSessionApi & { readSession: ReadMock; revokeSession: RevokeMock }

function stubSessions(overrides: Partial<AuthJsSessionApi> = {}): StubSessions {
  const readSession: ReadMock = vi.fn(overrides.readSession ?? (() => Promise.resolve(null)))
  const revokeSession: RevokeMock = vi.fn(
    overrides.revokeSession ?? (() => Promise.resolve(undefined))
  )
  return { readSession, revokeSession }
}

function validSessionBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    user: { id: 'au-1', email: 'a@b.co', emailVerified: true },
    expires: '2026-06-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('createAuthJsProvider', () => {
  it('exposes the authjs id and a copy of the cookie names', () => {
    const provider = createAuthJsProvider({
      sessions: stubSessions(),
      sessionCookieNames: cookieNames,
    })
    expect(provider.id).toBe('authjs')
    expect(provider.sessionCookieNames).toEqual(cookieNames)
    expect(provider.sessionCookieNames).not.toBe(cookieNames)
  })

  it('exposes clearing attributes when wired, omits the hook otherwise', () => {
    const sessionCookieClearOptions = (name: string) =>
      name === cookieNames[0] ? { secure: true as const } : undefined
    const wired = createAuthJsProvider({
      sessions: stubSessions(),
      sessionCookieNames: cookieNames,
      sessionCookieClearOptions,
    })
    expect(wired.sessionCookieClearOptions).toBe(sessionCookieClearOptions)
    const bare = createAuthJsProvider({ sessions: stubSessions(), sessionCookieNames: cookieNames })
    expect(bare.sessionCookieClearOptions).toBeUndefined()
    expect('sessionCookieClearOptions' in bare).toBe(false)
  })

  it('returns null when Auth.js reports no session', async () => {
    const sessions = stubSessions()
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
    const result = await provider.getSession(new Headers({ cookie: 'other=1' }))
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value).toBeNull()
    }
    expect(sessions.readSession).toHaveBeenCalledTimes(1)
  })

  it('narrows a valid session and takes the id from the base cookie', async () => {
    const sessions = stubSessions({
      readSession: vi.fn((): Promise<unknown> => Promise.resolve(validSessionBody())),
    })
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
    const result = await provider.getSession(
      new Headers({ cookie: 'authjs.session-token=tok-whole; other=1' })
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk() && result.value !== null) {
      expect(result.value.sessionId).toBe('tok-whole')
      expect(result.value.providerUserId).toBe('au-1')
      expect(result.value.email).toBe('a@b.co')
      expect(result.value.emailVerified).toBe(true)
      expect(result.value.expiresAt).toEqual(new Date('2026-06-01T00:00:00.000Z'))
    } else {
      expect.unreachable('expected a narrowed session')
    }
  })

  it('rejects a gapped chunk set instead of joining a garbage token (PAR-8)', async () => {
    const sessions = stubSessions({
      readSession: vi.fn((): Promise<unknown> => Promise.resolve(validSessionBody())),
    })
    const provider = createAuthJsProvider({
      sessions,
      sessionCookieNames: [...cookieNames, 'authjs.session-token.2'],
    })
    const gapped = await provider.getSession(
      new Headers({ cookie: 'authjs.session-token.0=aaa; authjs.session-token.2=ccc' })
    )
    expect(gapped.isErr()).toBe(true)
    if (gapped.isErr()) {
      expect(gapped.error).toBeInstanceOf(ProviderError)
      const cause: unknown = gapped.error.cause
      expect(String(cause instanceof Error ? cause.message : gapped.error.message)).toMatch(
        /non-contiguous/
      )
    }
  })

  it('joins chunk slots in order and prefers the whole base cookie', async () => {
    const sessions = stubSessions({
      readSession: vi.fn((): Promise<unknown> => Promise.resolve(validSessionBody())),
    })
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })

    const chunked = await provider.getSession(
      new Headers({ cookie: 'authjs.session-token.0=aaa; authjs.session-token.1=bbb' })
    )
    if (chunked.isOk() && chunked.value !== null) {
      expect(chunked.value.sessionId).toBe('aaabbb')
    } else {
      expect.unreachable('expected a chunk-joined session')
    }

    const both = await provider.getSession(
      new Headers({
        cookie:
          'authjs.session-token=whole; authjs.session-token.0=aaa; authjs.session-token.1=bbb',
      })
    )
    if (both.isOk() && both.value !== null) {
      expect(both.value.sessionId).toBe('whole')
    } else {
      expect.unreachable('expected the base cookie to win')
    }
  })

  it('accepts Date and numeric expiries', async () => {
    for (const expires of [
      new Date('2026-06-01T00:00:00.000Z'),
      Date.parse('2026-06-01T00:00:00.000Z'),
    ]) {
      const sessions = stubSessions({
        readSession: vi.fn((): Promise<unknown> => Promise.resolve(validSessionBody({ expires }))),
      })
      const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
      const result = await provider.getSession(new Headers({ cookie: 'authjs.session-token=t' }))
      expect(result.isOk()).toBe(true)
      if (result.isOk() && result.value !== null) {
        expect(result.value.expiresAt).toEqual(new Date('2026-06-01T00:00:00.000Z'))
      } else {
        expect.unreachable('expected a narrowed session')
      }
    }
  })

  it.each([
    ['non-object body', 'boom', 'expected a session object or null'],
    [
      'missing user',
      { user: null, expires: '2026-06-01T00:00:00.000Z' },
      'malformed session payload',
    ],
    [
      'missing user id',
      { user: { email: 'a@b.co', emailVerified: true }, expires: '2026-06-01T00:00:00.000Z' },
      'user id is missing',
    ],
    [
      'invalid email',
      {
        user: { id: 'au-1', email: 'nope', emailVerified: true },
        expires: '2026-06-01T00:00:00.000Z',
      },
      'invalid user email',
    ],
    [
      'missing verification flag',
      { user: { id: 'au-1', email: 'a@b.co' }, expires: '2026-06-01T00:00:00.000Z' },
      'emailVerified flag is missing',
    ],
    [
      'garbage expiry',
      { user: { id: 'au-1', email: 'a@b.co', emailVerified: true }, expires: 'not-a-date' },
      'expiry is missing or invalid',
    ],
    [
      'missing expiry',
      { user: { id: 'au-1', email: 'a@b.co', emailVerified: true } },
      'expiry is missing or invalid',
    ],
  ])('fails closed on %s', async (_label, body, message) => {
    const sessions = stubSessions({
      readSession: vi.fn((): Promise<unknown> => Promise.resolve(body)),
    })
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
    const result = await provider.getSession(new Headers({ cookie: 'authjs.session-token=t' }))
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(ProviderError)
      expect(result.error.message).toContain(message)
    }
  })

  it('rejects a session with no presented session cookie', async () => {
    const sessions = stubSessions({
      readSession: vi.fn((): Promise<unknown> => Promise.resolve(validSessionBody())),
    })
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
    for (const headers of [new Headers(), new Headers({ cookie: 'unrelated=1' })]) {
      const result = await provider.getSession(headers)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error.message).toContain('without a presented session cookie')
      }
    }
  })

  it('wraps session-read failures as ProviderError', async () => {
    const sessions = stubSessions({
      readSession: vi.fn((): Promise<unknown> => Promise.reject(new Error('authjs down'))),
    })
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
    const result = await provider.getSession(new Headers({ cookie: 'authjs.session-token=t' }))
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(ProviderError)
      expect(result.error.message).toContain('getSession')
    }
  })

  it('revokes through the injected api and wraps failures', async () => {
    const sessions = stubSessions()
    const provider = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
    const revoked = await provider.revokeSession('tok-1')
    expect(revoked.isOk()).toBe(true)
    expect(sessions.revokeSession).toHaveBeenCalledWith('tok-1')

    const failing = stubSessions({
      revokeSession: vi.fn((): Promise<unknown> => Promise.reject(new Error('db down'))),
    })
    const result = await createAuthJsProvider({
      sessions: failing,
      sessionCookieNames: cookieNames,
    }).revokeSession('tok-1')
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.message).toContain('revokeSession')
    }
  })
})
