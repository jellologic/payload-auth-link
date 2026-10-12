import { describe, expect, it } from 'vitest'
import {
  expiringCookieOptions,
  hostCookiePrefix,
  parseCookieHeader,
  resolveSecureCookies,
  secureCookiePrefix,
  serializeCookie,
} from '../cookies.js'

describe('serializeCookie', () => {
  it('serializes a minimal cookie', () => {
    expect(serializeCookie('session', 'abc')).toBe('session=abc')
  })

  it('serializes all options', () => {
    expect(
      serializeCookie('session', 'a b', {
        maxAge: 3600,
        domain: 'example.com',
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
      })
    ).toBe(
      'session=a%20b; Max-Age=3600; Domain=example.com; Path=/; HttpOnly; Secure; SameSite=Lax'
    )
  })

  it('renders strict and none', () => {
    expect(serializeCookie('a', 'b', { sameSite: 'strict' })).toContain('SameSite=Strict')
    expect(serializeCookie('a', 'b', { sameSite: 'none', secure: true })).toContain('SameSite=None')
  })

  it('rejects invalid names instead of emitting garbage', () => {
    expect(() => serializeCookie('has space', 'x')).toThrow('Invalid cookie name')
  })

  it('renders Partitioned when asked', () => {
    expect(serializeCookie('a', 'b', { partitioned: true, secure: true })).toContain('Partitioned')
  })
})

describe('expiringCookieOptions', () => {
  it('expires plain cookies without Secure', () => {
    expect(expiringCookieOptions('better-auth.session_token')).toEqual({ maxAge: 0, path: '/' })
  })

  it('adds Secure for prefixed names so the clearing write is accepted', () => {
    expect(expiringCookieOptions(`${secureCookiePrefix}authjs.session-token`)).toEqual({
      maxAge: 0,
      path: '/',
      secure: true,
    })
    expect(expiringCookieOptions(`${hostCookiePrefix}session`)).toEqual({
      maxAge: 0,
      path: '/',
      secure: true,
    })
  })
})

describe('secureCookiePrefix', () => {
  it('pins the RFC 6265bis spelling every provider imports', () => {
    expect(secureCookiePrefix).toBe('__Secure-')
  })
})

describe('resolveSecureCookies', () => {
  it('lets the explicit flag win over origin and environment', () => {
    expect(
      resolveSecureCookies(
        { useSecureCookies: true, baseURL: 'http://localhost:3000' },
        { nodeEnv: 'test' }
      )
    ).toBe(true)
    expect(
      resolveSecureCookies(
        { useSecureCookies: false, baseURL: 'https://app.example.com' },
        { nodeEnv: 'production' }
      )
    ).toBe(false)
  })

  it('follows the dynamic protocol ahead of the string check', () => {
    expect(resolveSecureCookies({ dynamicProtocol: 'https' }, { nodeEnv: 'test' })).toBe(true)
    expect(
      resolveSecureCookies(
        { dynamicProtocol: 'http', baseURL: 'https://app.example.com' },
        { nodeEnv: 'test' }
      )
    ).toBe(false)
  })

  it('treats an https baseURL as secure and any other string as not', () => {
    expect(resolveSecureCookies({ baseURL: 'https://app.example.com' }, { nodeEnv: 'test' })).toBe(
      true
    )
    expect(resolveSecureCookies({ baseURL: 'http://localhost:3000' }, { nodeEnv: 'test' })).toBe(
      false
    )
  })

  it('falls back to the injected production environment without an origin', () => {
    expect(resolveSecureCookies({}, { nodeEnv: 'production' })).toBe(true)
    expect(resolveSecureCookies({}, { nodeEnv: 'test' })).toBe(false)
  })

  it('treats an absent environment as non-production (callers inject the live env)', () => {
    expect(resolveSecureCookies({})).toBe(false)
    expect(resolveSecureCookies({}, {})).toBe(false)
    expect(resolveSecureCookies({}, { nodeEnv: undefined })).toBe(false)
  })
})

describe('parseCookieHeader', () => {
  it('parses pairs and decodes values', () => {
    const parsed = parseCookieHeader('a=1; b=a%20b')
    expect(parsed.get('a')).toBe('1')
    expect(parsed.get('b')).toBe('a b')
  })

  it('returns empty for null, empty, and malformed input', () => {
    expect(parseCookieHeader(null).size).toBe(0)
    expect(parseCookieHeader('').size).toBe(0)
    const parsed = parseCookieHeader('novalue; =x; ok=1')
    expect(parsed.size).toBe(1)
    expect(parsed.get('ok')).toBe('1')
  })

  it('keeps undecodable values raw', () => {
    expect(parseCookieHeader('a=%E0%A4%A').get('a')).toBe('%E0%A4%A')
  })
})
