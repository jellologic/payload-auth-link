import { describe, expect, it } from 'vitest'
import { decideAuthRedirect, safeRedirectPath } from '../redirect.js'

describe('safeRedirectPath', () => {
  it('passes safe in-app paths through', () => {
    expect(safeRedirectPath('/account')).toBe('/account')
    expect(safeRedirectPath('/account?tab=orders&page=2')).toBe('/account?tab=orders&page=2')
    expect(safeRedirectPath('/a/b/c#frag')).toBe('/a/b/c#frag')
  })

  it('falls back on absolute and protocol-relative URLs', () => {
    expect(safeRedirectPath('https://evil.example')).toBe('/account')
    expect(safeRedirectPath('http://evil.example/x')).toBe('/account')
    expect(safeRedirectPath('//evil.example/x')).toBe('/account')
    expect(safeRedirectPath('javascript:alert(1)')).toBe('/account')
  })

  it('falls back on backslashes, whitespace games, and control characters', () => {
    expect(safeRedirectPath('/\\evil.example')).toBe('/account')
    expect(safeRedirectPath('/account\\')).toBe('/account')
    expect(safeRedirectPath(' /account')).toBe('/account')
    expect(safeRedirectPath('/account ')).toBe('/account')
    expect(safeRedirectPath('/acc\tount')).toBe('/account')
    expect(safeRedirectPath('/acc\nount')).toBe('/account')
  })

  it('falls back on missing values and honors custom fallbacks', () => {
    expect(safeRedirectPath(null)).toBe('/account')
    expect(safeRedirectPath(undefined)).toBe('/account')
    expect(safeRedirectPath('')).toBe('/account')
    expect(safeRedirectPath('nota-path')).toBe('/account')
    expect(safeRedirectPath('https://evil.example', '/home')).toBe('/home')
    expect(safeRedirectPath(null, '/home')).toBe('/home')
  })
})

const cookieNames = ['better-auth.session_token']

function request(path: string, cookie?: string): Request {
  return new Request(`http://localhost:3200${path}`, cookie ? { headers: { cookie } } : undefined)
}

describe('decideAuthRedirect', () => {
  it('passes public string paths without cookies', () => {
    const options = { sessionCookieNames: cookieNames, publicPaths: ['/', '/about'] }
    expect(decideAuthRedirect(request('/'), options)).toBeNull()
    expect(decideAuthRedirect(request('/about'), options)).toBeNull()
    expect(decideAuthRedirect(request('/private'), options)).not.toBeNull()
  })

  it('matches public regexes against the pathname', () => {
    const options = { sessionCookieNames: cookieNames, publicPaths: [/^\/docs(\/|$)/] }
    expect(decideAuthRedirect(request('/docs/guide'), options)).toBeNull()
    expect(decideAuthRedirect(request('/private'), options)).not.toBeNull()
  })

  it('keeps the sign-in page public (no redirect loops)', () => {
    expect(decideAuthRedirect(request('/sign-in'), { sessionCookieNames: cookieNames })).toBeNull()
  })

  it('passes requests carrying any session cookie', () => {
    const options = { sessionCookieNames: cookieNames }
    expect(
      decideAuthRedirect(request('/private', 'other=1; better-auth.session_token=abc'), options)
    ).toBeNull()
    expect(decideAuthRedirect(request('/private', 'other=1'), options)).not.toBeNull()
    expect(decideAuthRedirect(request('/private'), options)).not.toBeNull()
  })

  it('redirects anonymous traffic with the intercepted path', () => {
    const target = decideAuthRedirect(request('/private?tab=1'), {
      sessionCookieNames: cookieNames,
    })
    expect(target?.toString()).toBe('http://localhost:3200/sign-in?redirect=%2Fprivate%3Ftab%3D1')
  })

  it('honors custom sign-in path and redirect param', () => {
    const options = {
      sessionCookieNames: cookieNames,
      signInPath: '/login',
      redirectParam: 'next',
    }
    expect(decideAuthRedirect(request('/login'), options)).toBeNull()
    expect(decideAuthRedirect(request('/private'), options)?.toString()).toBe(
      'http://localhost:3200/login?next=%2Fprivate'
    )
  })

  it('fails closed with empty cookie names', () => {
    expect(
      decideAuthRedirect(request('/private', 'a=b'), { sessionCookieNames: [] })
    ).not.toBeNull()
  })
})
