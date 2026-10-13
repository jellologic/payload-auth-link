import { describe, expect, it, vi } from 'vitest'
import { InvalidConfigError } from '@payload-auth-link/core'
import { createSessionVerifier, resolveSessionUrl } from '../verify.js'

const user = { id: 'user-1', collection: 'users', email: 'user@example.com', roles: ['member'] }

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function stubFetch(response: Response | Error) {
  const fetchImpl = vi.fn()
  if (response instanceof Error) {
    fetchImpl.mockRejectedValue(response)
  } else {
    fetchImpl.mockResolvedValue(response)
  }
  return fetchImpl
}

function headers(entries: Record<string, string> = {}): Headers {
  return new Headers({ host: 'localhost:3000', ...entries })
}

describe('resolveSessionUrl', () => {
  it('passes absolute endpoints through', () => {
    expect(resolveSessionUrl(headers(), 'https://auth.example.com/session')).toBe(
      'https://auth.example.com/session'
    )
  })

  it('resolves relative endpoints against baseUrl', () => {
    expect(resolveSessionUrl(headers(), '/api/auth-link/session', 'https://app.example.com')).toBe(
      'https://app.example.com/api/auth-link/session'
    )
  })

  it('derives the origin from forwarded headers first', () => {
    const forwarded = headers({
      'x-forwarded-host': 'app.example.com',
      'x-forwarded-proto': 'https',
    })
    expect(resolveSessionUrl(forwarded)).toBe('https://app.example.com/api/auth-link/session')
  })

  it('falls back to the direct host over http', () => {
    expect(resolveSessionUrl(headers())).toBe('http://localhost:3000/api/auth-link/session')
  })

  it('throws when no host can be found', () => {
    expect(() => resolveSessionUrl(new Headers())).toThrow(InvalidConfigError)
  })

  it('throws when the host fallback is disabled without baseUrl', () => {
    expect(() => resolveSessionUrl(headers(), '/api/auth-link/session', undefined, false)).toThrow(
      InvalidConfigError
    )
  })

  it('throws InvalidConfigError (never TypeError) on a malformed baseUrl', () => {
    expect(() => resolveSessionUrl(headers(), '/api/auth-link/session', 'nope')).toThrow(
      InvalidConfigError
    )
  })
})

describe('createSessionVerifier', () => {
  it('forwards cookies and narrows the user', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({ fetchImpl })
    const result = await verify(headers({ cookie: 'better-auth.session_token=abc' }))
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith('http://localhost:3000/api/auth-link/session', {
      headers: { cookie: 'better-auth.session_token=abc', accept: 'application/json' },
      cache: 'no-store',
    })
  })

  it('surfaces PORT-4 facts and still accepts old payloads without them', async () => {
    const rich = {
      ...user,
      assurance: { methods: ['magic-link'], mfa: 'unknown' },
      actor: { kind: 'provider-only', providerUserId: 'operator-1' },
      organizationId: 'org-1',
    }
    const headersWithCookie = headers({ cookie: 'a=b' })
    const richVerify = createSessionVerifier({ fetchImpl: stubFetch(jsonResponse({ user: rich })) })
    await expect(richVerify(headersWithCookie)).resolves.toEqual(rich)
    // An older server omits the optional fields; the user still verifies.
    const oldVerify = createSessionVerifier({ fetchImpl: stubFetch(jsonResponse({ user })) })
    await expect(oldVerify(headersWithCookie)).resolves.toEqual(user)
  })

  it('degrades malformed PORT-4 facts instead of nuking the verified user', async () => {
    // Forward-compat wire parsing: a malformed optional actor
    // degrades to absent and malformed assurance to 'unknown'
    // (fail-closed for policy) — server authz never uses this
    // parser, so no impersonation marker is laundered server-side.
    const tampered = { ...user, actor: { providerUserId: '' }, assurance: 'strong' }
    const verify = createSessionVerifier({ fetchImpl: stubFetch(jsonResponse({ user: tampered })) })
    await expect(verify(headers({ cookie: 'a=b' }))).resolves.toEqual({
      ...user,
      assurance: { methods: 'unknown', mfa: 'unknown' },
    })
  })

  it('skips the fetch without cookies', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({ fetchImpl })
    await expect(verify(headers())).resolves.toBeNull()
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('fails closed on transport and protocol failures', async () => {
    const cookie = headers({ cookie: 'a=b' })
    const failures: Array<Response | Error> = [
      new Error('down'),
      jsonResponse({}, 401),
      jsonResponse({}, 500),
      new Response('not-json{', { status: 200 }),
      jsonResponse([user]),
      jsonResponse({ user: { ...user, email: 'bad' } }),
    ]
    for (const failure of failures) {
      const verify = createSessionVerifier({ fetchImpl: stubFetch(failure) })
      await expect(verify(cookie)).resolves.toBeNull()
    }
  })

  it('reports transport errors through onError', async () => {
    const onError = vi.fn()
    const verify = createSessionVerifier({ fetchImpl: stubFetch(new Error('down')), onError })
    await expect(verify(headers({ cookie: 'a=b' }))).resolves.toBeNull()
    expect(onError).toHaveBeenCalledTimes(1)
  })

  it('throws at construction in production without baseUrl', () => {
    expect(() =>
      createSessionVerifier({
        fetchImpl: stubFetch(jsonResponse({ user })),
        environment: { nodeEnv: 'production' },
      })
    ).toThrow(InvalidConfigError)
  })

  it('throws at construction on a malformed baseUrl', () => {
    expect(() =>
      createSessionVerifier({ baseUrl: 'nope', fetchImpl: stubFetch(jsonResponse({ user })) })
    ).toThrow(InvalidConfigError)
    expect(() =>
      createSessionVerifier({
        baseUrl: 'ftp://files.example.com',
        fetchImpl: stubFetch(jsonResponse({ user })),
      })
    ).toThrow(InvalidConfigError)
  })

  it('uses baseUrl in production and forbids the host fallback per request', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({
      baseUrl: 'https://app.example.com',
      fetchImpl,
      environment: { nodeEnv: 'production' },
    })
    const result = await verify(headers({ cookie: 'a=b' }))
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith('https://app.example.com/api/auth-link/session', {
      headers: { cookie: 'a=b', accept: 'application/json' },
      cache: 'no-store',
    })
  })

  it('keeps the forwarded-header fallback outside production', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({
      fetchImpl,
      environment: { nodeEnv: 'development' },
    })
    const result = await verify(
      headers({
        cookie: 'a=b',
        'x-forwarded-host': 'app.example.com',
        'x-forwarded-proto': 'https',
      })
    )
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://app.example.com/api/auth-link/session',
      expect.anything()
    )
  })
})
