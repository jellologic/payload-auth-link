import { secureCookiePrefix } from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import { getAuthJsSessionCookieClearOptions, getAuthJsSessionCookieNames } from '../cookies.js'

describe('getAuthJsSessionCookieNames', () => {
  it('returns the default session token cookie plus chunk slots', () => {
    expect(getAuthJsSessionCookieNames({})).toEqual([
      'authjs.session-token',
      'authjs.session-token.0',
      'authjs.session-token.1',
      'authjs.session-token.2',
    ])
  })

  it('prefixes secure cookies for https origins', () => {
    expect(getAuthJsSessionCookieNames({ baseURL: 'https://app.example.com' })[0]).toBe(
      '__Secure-authjs.session-token'
    )
    expect(getAuthJsSessionCookieNames({ baseURL: 'http://localhost:3000' })[0]).toBe(
      'authjs.session-token'
    )
  })

  it('pins the secure prefix spelling to core (logout clearing depends on it)', () => {
    const names = getAuthJsSessionCookieNames({ baseURL: 'https://app.example.com' })
    expect(names[0]?.startsWith(secureCookiePrefix)).toBe(true)
  })

  it('shares the production-secure rule: production without an origin is secure', () => {
    expect(getAuthJsSessionCookieNames({}, { nodeEnv: 'production' })[0]).toBe(
      '__Secure-authjs.session-token'
    )
    expect(getAuthJsSessionCookieNames({}, { nodeEnv: 'test' })[0]).toBe('authjs.session-token')
  })

  it('reads the live NODE_ENV when no environment is injected', () => {
    const env = process.env as unknown as Record<string, string | undefined>
    const previous = env.NODE_ENV
    try {
      env.NODE_ENV = 'production'
      expect(getAuthJsSessionCookieNames({})[0]).toBe('__Secure-authjs.session-token')
      delete env.NODE_ENV
      expect(getAuthJsSessionCookieNames({})[0]).toBe('authjs.session-token')
    } finally {
      if (previous === undefined) {
        delete env.NODE_ENV
      } else {
        env.NODE_ENV = previous
      }
    }
  })

  it('lets useSecureCookies win over the origin rule', () => {
    expect(
      getAuthJsSessionCookieNames({ useSecureCookies: true, baseURL: 'http://localhost:3000' })[0]
    ).toBe('__Secure-authjs.session-token')
    expect(
      getAuthJsSessionCookieNames({
        useSecureCookies: false,
        baseURL: 'https://app.example.com',
      })[0]
    ).toBe('authjs.session-token')
  })

  it('mirrors custom session token names into every slot', () => {
    expect(getAuthJsSessionCookieNames({ sessionTokenName: 'acme.session' })).toEqual([
      'acme.session',
      'acme.session.0',
      'acme.session.1',
      'acme.session.2',
    ])
  })

  it('sizes the chunk slots for giant-claim deployments', () => {
    expect(getAuthJsSessionCookieNames({ chunkSlots: 5 })).toEqual([
      'authjs.session-token',
      'authjs.session-token.0',
      'authjs.session-token.1',
      'authjs.session-token.2',
      'authjs.session-token.3',
      'authjs.session-token.4',
    ])
    expect(getAuthJsSessionCookieNames({ chunkSlots: 0 })).toEqual(['authjs.session-token'])
  })
})

describe('getAuthJsSessionCookieClearOptions', () => {
  it('reports Secure for https origins across every chunk slot', () => {
    const clear = getAuthJsSessionCookieClearOptions({ baseURL: 'https://app.example.com' })
    expect(clear('__Secure-authjs.session-token')).toEqual({ secure: true })
    expect(clear('__Secure-authjs.session-token.2')).toEqual({ secure: true })
    expect(clear('authjs.session-token')).toBeUndefined()
  })

  it('keeps Secure for custom names when Auth.js sets it (prefix inference would miss)', () => {
    const clear = getAuthJsSessionCookieClearOptions({
      baseURL: 'https://app.example.com',
      sessionTokenName: 'acme.session',
    })
    expect(clear('acme.session')).toEqual({ secure: true })
    expect(clear('acme.session.0')).toEqual({ secure: true })
  })

  it('omits Secure for http and honors explicit option overrides', () => {
    const clear = getAuthJsSessionCookieClearOptions({ baseURL: 'http://localhost:3000' })
    expect(clear('authjs.session-token')).toEqual({})
    const overridden = getAuthJsSessionCookieClearOptions({
      baseURL: 'https://app.example.com',
      sessionTokenOptions: { secure: false, domain: 'example.com', path: '/app' },
    })
    expect(overridden('__Secure-authjs.session-token')).toEqual({
      domain: 'example.com',
      path: '/app',
    })
  })

  it('reports Secure clearing in production without an origin', () => {
    const clear = getAuthJsSessionCookieClearOptions({}, { nodeEnv: 'production' })
    expect(clear('__Secure-authjs.session-token')).toEqual({ secure: true })
    expect(clear('__Secure-authjs.session-token.0')).toEqual({ secure: true })
  })

  it('returns fresh objects so callers cannot alias the lookup', () => {
    const clear = getAuthJsSessionCookieClearOptions({})
    const first = clear('authjs.session-token')
    const second = clear('authjs.session-token')
    expect(first).toEqual(second)
    expect(first).not.toBe(second)
  })
})
