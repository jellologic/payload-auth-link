import { secureCookiePrefix } from '@payload-auth-link/core'
import type { BetterAuthOptions } from 'better-auth'
import { createCookieGetter, getCookies } from 'better-auth/cookies'
import { describe, expect, it } from 'vitest'
import {
  getBetterAuthLogoutCookieNames,
  getBetterAuthSessionCookieClearOptions,
  getBetterAuthSessionCookieNames,
} from '../cookies.js'

describe('getBetterAuthSessionCookieNames', () => {
  it('returns the default session token cookie', () => {
    expect(getBetterAuthSessionCookieNames({}, { nodeEnv: 'test' })).toEqual([
      'better-auth.session_token',
    ])
  })

  it('adds the session data cookie when the cookie cache is enabled', () => {
    expect(
      getBetterAuthSessionCookieNames(
        { session: { cookieCache: { enabled: true } } },
        { nodeEnv: 'test' }
      )
    ).toEqual(['better-auth.session_token', 'better-auth.session_data'])
  })

  it('honors the cookie prefix and per-cookie name overrides', () => {
    expect(
      getBetterAuthSessionCookieNames(
        {
          advanced: {
            cookiePrefix: 'acme',
            cookies: { session_token: { name: 'acme.session' } },
          },
          session: { cookieCache: { enabled: true } },
        },
        { nodeEnv: 'test' }
      )
    ).toEqual(['acme.session', 'acme.session_data'])
  })

  it('prefixes secure cookies when useSecureCookies is set', () => {
    expect(
      getBetterAuthSessionCookieNames({ advanced: { useSecureCookies: true } }, { nodeEnv: 'test' })
    ).toEqual(['__Secure-better-auth.session_token'])
  })

  it('pins the secure prefix spelling to core (logout clearing depends on it)', () => {
    const names = getBetterAuthSessionCookieNames(
      { advanced: { useSecureCookies: true } },
      { nodeEnv: 'test' }
    )
    expect(names[0]?.startsWith(secureCookiePrefix)).toBe(true)
  })

  it('prefixes secure cookies for https base URLs', () => {
    expect(
      getBetterAuthSessionCookieNames({ baseURL: 'https://app.example.com' }, { nodeEnv: 'test' })
    ).toEqual(['__Secure-better-auth.session_token'])
    expect(
      getBetterAuthSessionCookieNames({ baseURL: 'http://localhost:3000' }, { nodeEnv: 'test' })
    ).toEqual(['better-auth.session_token'])
  })

  it('prefixes secure cookies in production without a base URL', () => {
    expect(getBetterAuthSessionCookieNames({}, { nodeEnv: 'production' })).toEqual([
      '__Secure-better-auth.session_token',
    ])
  })

  it('follows the dynamic baseURL protocol', () => {
    // Upstream's runtime reads `baseURL.protocol` for object-form base URLs
    // (see `createCookieGetter`); the cast covers the type lag.
    const https = { protocol: 'https' } as unknown as string
    const http = { protocol: 'http' } as unknown as string
    expect(getBetterAuthSessionCookieNames({ baseURL: https }, { nodeEnv: 'test' })).toEqual([
      '__Secure-better-auth.session_token',
    ])
    expect(getBetterAuthSessionCookieNames({ baseURL: http }, { nodeEnv: 'test' })).toEqual([
      'better-auth.session_token',
    ])
  })

  it('ignores a non-string dynamic protocol', () => {
    const weird = { protocol: 443 } as unknown as string
    expect(getBetterAuthSessionCookieNames({ baseURL: weird }, { nodeEnv: 'test' })).toEqual([
      'better-auth.session_token',
    ])
  })

  it('treats a missing NODE_ENV as non-production', () => {
    // `NODE_ENV` is typed readonly; the cast only serves this test's
    // save/delete/restore dance.
    const env = process.env as unknown as Record<string, string | undefined>
    const previous = env.NODE_ENV
    delete env.NODE_ENV
    try {
      expect(getBetterAuthSessionCookieNames({})).toEqual(['better-auth.session_token'])
    } finally {
      if (previous === undefined) {
        delete env.NODE_ENV
      } else {
        env.NODE_ENV = previous
      }
    }
  })
})

describe('SDK drift', () => {
  // Every case below is NODE_ENV-independent on both sides: ours takes an
  // injected test env, and the real getter only reads its load-time
  // `isProduction` when no explicit flag, dynamic protocol, or string
  // baseURL is set. The production fallback gets its own drift test
  // underneath (the getter freezes NODE_ENV at import time).
  const driftCases: Array<{
    readonly name: string
    readonly options: BetterAuthOptions
    readonly cookieCache: boolean
  }> = [
    {
      name: 'https baseURL',
      options: { baseURL: 'https://app.example.com' },
      cookieCache: false,
    },
    {
      name: 'http baseURL',
      options: { baseURL: 'http://localhost:3000' },
      cookieCache: false,
    },
    {
      name: 'explicit flag wins over http',
      options: { baseURL: 'http://localhost:3000', advanced: { useSecureCookies: true } },
      cookieCache: false,
    },
    {
      name: 'explicit opt-out wins over https',
      options: { baseURL: 'https://app.example.com', advanced: { useSecureCookies: false } },
      cookieCache: false,
    },
    {
      name: 'dynamic https protocol',
      options: { baseURL: { protocol: 'https' } as unknown as string },
      cookieCache: false,
    },
    {
      name: 'dynamic http protocol',
      options: { baseURL: { protocol: 'http' } as unknown as string },
      cookieCache: false,
    },
    {
      name: 'custom prefix, names, and cookie cache',
      options: {
        baseURL: 'https://app.example.com',
        advanced: {
          cookiePrefix: 'acme',
          cookies: { session_token: { name: 'acme.session' } },
        },
        session: { cookieCache: { enabled: true } },
      },
      cookieCache: true,
    },
  ]

  it.each(driftCases)('$name matches the real cookie getter', ({ options, cookieCache }) => {
    const ours = getBetterAuthSessionCookieNames(options, { nodeEnv: 'test' })
    const sdk = getCookies(options)
    expect(ours[0]).toBe(sdk.sessionToken.name)
    if (cookieCache) {
      expect(ours[1]).toBe(sdk.sessionData.name)
    } else {
      expect(ours).toHaveLength(1)
    }
  })

  it('matches the real getter on the fallback leg under the ambient environment', () => {
    // The real getter freezes NODE_ENV at import time and vitest reuses
    // the external module across resets (probed), so no in-process test
    // can re-freeze it: feed ours the same ambient value instead, so both
    // sides evaluate the identical fallback input. The production branch
    // itself is pinned by the shared-rule unit tests plus the
    // source-verified `isProduction` fallback (see `secureCookiesEnabled`).
    const nodeEnv = process.env.NODE_ENV ?? ''
    const ours = getBetterAuthSessionCookieNames({}, { nodeEnv })
    expect(ours).toEqual([getCookies({}).sessionToken.name])
  })
})

describe('getBetterAuthSessionCookieClearOptions', () => {
  it('reports Secure for https origins and undefined for unknown names', () => {
    const clear = getBetterAuthSessionCookieClearOptions(
      { baseURL: 'https://app.example.com' },
      { nodeEnv: 'test' }
    )
    expect(clear('__Secure-better-auth.session_token')).toEqual({ secure: true })
    expect(clear('better-auth.session_token')).toBeUndefined()
    expect(clear('other')).toBeUndefined()
  })

  it('resolves overridden names with their secure attributes', () => {
    const clear = getBetterAuthSessionCookieClearOptions(
      {
        baseURL: 'https://app.example.com',
        advanced: { cookies: { session_token: { name: 'acme.session' } } },
      },
      { nodeEnv: 'test' }
    )
    expect(clear('__Secure-acme.session')).toEqual({ secure: true })
  })

  it('prefers per-cookie attributes, then defaults, then the secure rule', () => {
    const clear = getBetterAuthSessionCookieClearOptions(
      {
        advanced: {
          defaultCookieAttributes: { domain: 'example.com' },
          cookies: { session_token: { attributes: { domain: 'auth.example.com', path: '/s' } } },
        },
      },
      { nodeEnv: 'test' }
    )
    expect(clear('better-auth.session_token')).toEqual({
      domain: 'auth.example.com',
      path: '/s',
    })
    const fallback = getBetterAuthSessionCookieClearOptions(
      { advanced: { defaultCookieAttributes: { domain: 'example.com' } } },
      { nodeEnv: 'test' }
    )
    expect(fallback('better-auth.session_token')).toEqual({ domain: 'example.com' })
  })

  it('covers admin_session with the session token attributes BA sets it with (CAP-8a)', () => {
    const clear = getBetterAuthSessionCookieClearOptions(
      {
        baseURL: 'https://app.example.com',
        advanced: {
          cookies: { session_token: { attributes: { domain: 'auth.example.com' } } },
        },
      },
      { nodeEnv: 'test' }
    )
    expect(clear('__Secure-better-auth.admin_session')).toEqual({
      secure: true,
      domain: 'auth.example.com',
    })
    const plain = getBetterAuthSessionCookieClearOptions({}, { nodeEnv: 'test' })
    expect(plain('better-auth.admin_session')).toEqual({})
  })

  it('covers the cookie-cache and dont_remember cookies whether or not the cache is enabled', () => {
    const cached = getBetterAuthSessionCookieClearOptions(
      { session: { cookieCache: { enabled: true } } },
      { nodeEnv: 'test' }
    )
    expect(cached('better-auth.session_data')).toEqual({})
    // A disabled cache may still have left a cookie behind: logout
    // clears it with its configured attributes.
    const plain = getBetterAuthSessionCookieClearOptions(
      { advanced: { cookies: { session_data: { attributes: { domain: 'example.com' } } } } },
      { nodeEnv: 'test' }
    )
    expect(plain('better-auth.session_data')).toEqual({ domain: 'example.com' })
    expect(plain('better-auth.dont_remember')).toEqual({})
  })
})

describe('getBetterAuthLogoutCookieNames (CAP-8a)', () => {
  it('never returns a session-indicating name', () => {
    const cases: BetterAuthOptions[] = [
      {},
      { advanced: { useSecureCookies: true } },
      { session: { cookieCache: { enabled: true } } },
      { advanced: { cookiePrefix: 'acme' } },
    ]
    for (const options of cases) {
      const session = getBetterAuthSessionCookieNames(options, { nodeEnv: 'test' })
      const logout = getBetterAuthLogoutCookieNames(options, { nodeEnv: 'test' })
      expect(logout.filter((name) => session.includes(name))).toEqual([])
    }
  })

  it('covers admin_session, dont_remember, session_data and both __Secure- variants', () => {
    expect([...getBetterAuthLogoutCookieNames({}, { nodeEnv: 'test' })].sort()).toEqual(
      [
        'better-auth.admin_session',
        'better-auth.dont_remember',
        'better-auth.session_data',
        '__Secure-better-auth.session_token',
        '__Secure-better-auth.admin_session',
        '__Secure-better-auth.dont_remember',
        '__Secure-better-auth.session_data',
      ].sort()
    )
    expect(
      [
        ...getBetterAuthLogoutCookieNames(
          { advanced: { useSecureCookies: true, cookiePrefix: 'acme' } },
          { nodeEnv: 'test' }
        ),
      ].sort()
    ).toEqual(
      [
        '__Secure-acme.admin_session',
        '__Secure-acme.dont_remember',
        '__Secure-acme.session_data',
        'acme.session_token',
        'acme.admin_session',
        'acme.dont_remember',
        'acme.session_data',
      ].sort()
    )
  })

  it("matches BA's real createCookieGetter for every logout-only key", () => {
    const cases: BetterAuthOptions[] = [
      { baseURL: 'https://app.example.com' },
      { baseURL: 'http://localhost:3000' },
      {
        baseURL: 'https://app.example.com',
        advanced: { cookiePrefix: 'acme' },
      },
      {
        baseURL: 'https://app.example.com',
        advanced: { cookies: { dont_remember: { name: 'custom_dr' } } },
      },
    ]
    for (const options of cases) {
      const getter = createCookieGetter(options)
      const logout = getBetterAuthLogoutCookieNames(options, { nodeEnv: 'test' })
      const session = getBetterAuthSessionCookieNames(options, { nodeEnv: 'test' })
      // Every name BA can write for these keys is session- or logout-covered.
      for (const key of ['admin_session', 'dont_remember', 'session_data', 'session_token']) {
        const name = getter(key).name
        expect([...logout, ...session]).toContain(name)
        const toggled = name.startsWith(secureCookiePrefix)
          ? name.slice(secureCookiePrefix.length)
          : `${secureCookiePrefix}${name}`
        expect([...logout, ...session]).toContain(toggled)
      }
    }
  })
})
