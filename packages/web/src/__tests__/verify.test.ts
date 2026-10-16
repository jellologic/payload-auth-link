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

const dev = { nodeEnv: 'development' }

function expectedInit(cookie: string) {
  return {
    headers: { cookie, accept: 'application/json' },
    cache: 'no-store',
    redirect: 'manual',
    signal: expect.any(AbortSignal) as unknown,
  }
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

  it('ignores forwarded headers unless trustProxy is set', () => {
    const forwarded = headers({
      'x-forwarded-host': 'evil.example.com',
      'x-forwarded-proto': 'https',
    })
    expect(resolveSessionUrl(forwarded, undefined, undefined, true)).toBe(
      'http://localhost:3000/api/auth-link/session'
    )
    const proxied = headers({ 'x-forwarded-host': '127.0.0.1:8080', 'x-forwarded-proto': 'https' })
    expect(resolveSessionUrl(proxied, undefined, undefined, true, { trustProxy: true })).toBe(
      'https://127.0.0.1:8080/api/auth-link/session'
    )
  })

  it('rejects a forwarded host outside the allowlist even under trustProxy', () => {
    const forwarded = headers({ 'x-forwarded-host': 'evil.example.com' })
    expect(() =>
      resolveSessionUrl(forwarded, undefined, undefined, true, { trustProxy: true })
    ).toThrow(InvalidConfigError)
  })

  it('rejects non-http forwarded schemes', () => {
    for (const proto of ['file', 'gopher', 'javascript', 'ftp']) {
      const forwarded = headers({ 'x-forwarded-proto': proto })
      expect(() =>
        resolveSessionUrl(forwarded, undefined, undefined, true, { trustProxy: true })
      ).toThrow(InvalidConfigError)
    }
  })

  it('rejects direct hosts outside the allowlist, and accepts configured ones', () => {
    for (const host of ['evil.example.com', '169.254.169.254', 'localhost.evil.com', 'a@b']) {
      expect(() => resolveSessionUrl(new Headers({ host }), undefined, undefined, true)).toThrow(
        InvalidConfigError
      )
    }
    expect(resolveSessionUrl(new Headers({ host: '[::1]:3000' }), undefined, undefined, true)).toBe(
      'http://[::1]:3000/api/auth-link/session'
    )
    expect(
      resolveSessionUrl(new Headers({ host: 'dev.test:3000' }), undefined, undefined, true, {
        allowedHosts: ['dev.test'],
      })
    ).toBe('http://dev.test:3000/api/auth-link/session')
  })

  it('falls back to the direct host over http only when explicitly allowed', () => {
    expect(resolveSessionUrl(headers(), undefined, undefined, true)).toBe(
      'http://localhost:3000/api/auth-link/session'
    )
    expect(() => resolveSessionUrl(headers())).toThrow(InvalidConfigError)
  })

  it('throws when no host can be found', () => {
    expect(() => resolveSessionUrl(new Headers(), undefined, undefined, true)).toThrow(
      InvalidConfigError
    )
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

  it('rejects protocol-relative and non-http endpoints', () => {
    for (const endpoint of [
      '//evil.example.com/session',
      '/\\evil.example.com/session',
      'javascript:alert(1)',
      'file:///etc/passwd',
      'api/auth-link/session',
      // URL parsing strips these, turning the path protocol-relative.
      '/\t/evil.example.com/session',
      '/\n/evil.example.com/session',
      '/\r\\evil.example.com/session',
      '/api/auth-link/session ',
    ]) {
      expect(() => resolveSessionUrl(headers(), endpoint, 'https://app.example.com')).toThrow(
        InvalidConfigError
      )
      expect(() =>
        createSessionVerifier({ sessionEndpoint: endpoint, baseUrl: 'https://app.example.com' })
      ).toThrow(InvalidConfigError)
    }
  })
})

describe('createSessionVerifier', () => {
  it('forwards cookies and narrows the user', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({ fetchImpl, environment: dev })
    const result = await verify(headers({ cookie: 'better-auth.session_token=abc' }))
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://localhost:3000/api/auth-link/session',
      expectedInit('better-auth.session_token=abc')
    )
  })

  it('surfaces PORT-4 facts and still accepts old payloads without them', async () => {
    const rich = {
      ...user,
      assurance: { methods: ['magic-link'], mfa: 'unknown' },
      actor: { kind: 'provider-only', providerUserId: 'operator-1' },
      organizationId: 'org-1',
    }
    const headersWithCookie = headers({ cookie: 'a=b' })
    const richVerify = createSessionVerifier({
      fetchImpl: stubFetch(jsonResponse({ user: rich })),
      environment: dev,
    })
    await expect(richVerify(headersWithCookie)).resolves.toEqual(rich)
    // An older server omits the optional fields; the user still verifies.
    const oldVerify = createSessionVerifier({
      fetchImpl: stubFetch(jsonResponse({ user })),
      environment: dev,
    })
    await expect(oldVerify(headersWithCookie)).resolves.toEqual(user)
  })

  it('degrades malformed PORT-4 facts instead of nuking the verified user', async () => {
    // Forward-compat wire parsing: a malformed optional actor
    // degrades to absent and malformed assurance to 'unknown'
    // (fail-closed for policy) — server authz never uses this
    // parser, so no impersonation marker is laundered server-side.
    const tampered = { ...user, actor: { providerUserId: '' }, assurance: 'strong' }
    const verify = createSessionVerifier({
      fetchImpl: stubFetch(jsonResponse({ user: tampered })),
      environment: dev,
    })
    await expect(verify(headers({ cookie: 'a=b' }))).resolves.toEqual({
      ...user,
      assurance: { methods: 'unknown', mfa: 'unknown' },
    })
  })

  it('skips the fetch without cookies', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({ fetchImpl, environment: dev })
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
      const verify = createSessionVerifier({ fetchImpl: stubFetch(failure), environment: dev })
      await expect(verify(cookie)).resolves.toBeNull()
    }
  })

  it('reports transport errors through onError', async () => {
    const onError = vi.fn()
    const verify = createSessionVerifier({
      fetchImpl: stubFetch(new Error('down')),
      onError,
      environment: dev,
    })
    await expect(verify(headers({ cookie: 'a=b' }))).resolves.toBeNull()
    expect(onError).toHaveBeenCalledTimes(1)
  })

  it('refuses the host fallback for every environment but development', () => {
    for (const nodeEnv of [
      undefined,
      '',
      'production',
      'staging',
      'test',
      'preview',
      'Development',
    ]) {
      expect(() =>
        createSessionVerifier({
          fetchImpl: stubFetch(jsonResponse({ user })),
          environment: { nodeEnv },
        })
      ).toThrow(InvalidConfigError)
    }
  })

  it('allows an absolute sessionEndpoint without baseUrl outside development', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({
      sessionEndpoint: 'https://app.example.com/api/auth-link/session',
      fetchImpl,
      environment: { nodeEnv: 'production' },
    })
    await expect(verify(headers({ cookie: 'a=b', host: 'evil.example.com' }))).resolves.toEqual(
      user
    )
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://app.example.com/api/auth-link/session',
      expectedInit('a=b')
    )
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
    const result = await verify(
      headers({ cookie: 'a=b', 'x-forwarded-host': 'evil.example.com', host: 'evil.example.com' })
    )
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://app.example.com/api/auth-link/session',
      expectedInit('a=b')
    )
  })

  it('ignores forwarded headers in development without trustProxy', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const onError = vi.fn()
    const verify = createSessionVerifier({ fetchImpl, onError, environment: dev })
    const result = await verify(
      headers({
        cookie: 'a=b',
        'x-forwarded-host': 'evil.example.com',
        'x-forwarded-proto': 'https',
      })
    )
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://localhost:3000/api/auth-link/session',
      expect.anything()
    )
    expect(onError).not.toHaveBeenCalled()
  })

  it('honors forwarded headers in development under trustProxy', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({ fetchImpl, trustProxy: true, environment: dev })
    const result = await verify(
      headers({
        cookie: 'a=b',
        'x-forwarded-host': '127.0.0.1:8443',
        'x-forwarded-proto': 'https',
      })
    )
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://127.0.0.1:8443/api/auth-link/session',
      expect.anything()
    )
  })

  it('fails closed on a non-allowlisted host or non-http proto, without fetching', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const onError = vi.fn()
    const verify = createSessionVerifier({
      fetchImpl,
      onError,
      trustProxy: true,
      environment: dev,
    })
    await expect(
      verify(new Headers({ cookie: 'a=b', host: 'attacker.example.com' }))
    ).resolves.toBeNull()
    await expect(
      verify(headers({ cookie: 'a=b', 'x-forwarded-host': 'attacker.example.com' }))
    ).resolves.toBeNull()
    await expect(
      verify(headers({ cookie: 'a=b', 'x-forwarded-proto': 'file' }))
    ).resolves.toBeNull()
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledTimes(3)
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(InvalidConfigError)
  })

  it('accepts configured development hosts', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const verify = createSessionVerifier({
      fetchImpl,
      allowedDevelopmentHosts: ['app.localhost'],
      environment: dev,
    })
    await expect(
      verify(new Headers({ cookie: 'a=b', host: 'app.localhost:3000' }))
    ).resolves.toEqual(user)
    await expect(verify(headers({ cookie: 'a=b' }))).resolves.toBeNull()
  })

  it('times out and fails closed, reporting through onError', async () => {
    const onError = vi.fn()
    const fetchImpl = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal
          signal?.addEventListener('abort', () => {
            reject(signal.reason as Error)
          })
        })
    )
    const verify = createSessionVerifier({ fetchImpl, onError, timeoutMs: 20, environment: dev })
    await expect(verify(headers({ cookie: 'a=b' }))).resolves.toBeNull()
    expect(onError).toHaveBeenCalledTimes(1)
    expect((onError.mock.calls[0]?.[0] as Error).name).toBe('TimeoutError')
  })

  it('rejects a non-positive timeout at construction', () => {
    for (const timeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() =>
        createSessionVerifier({ baseUrl: 'https://app.example.com', timeoutMs })
      ).toThrow(InvalidConfigError)
    }
  })
})
