import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { safeRedirectPath } from '../redirect.js'

describe('safeRedirectPath destination policy (PAR-11)', () => {
  it('falls back for the sign-in page, with or without a query or hash', () => {
    expect(safeRedirectPath('/sign-in')).toBe('/account')
    expect(safeRedirectPath('/sign-in?redirect=%2Faccount')).toBe('/account')
    expect(safeRedirectPath('/sign-in#top')).toBe('/account')
    expect(safeRedirectPath('/login', '/home', { signInPath: '/login' })).toBe('/home')
  })

  it('falls back for API destinations, never for look-alike pages', () => {
    expect(safeRedirectPath('/api')).toBe('/account')
    expect(safeRedirectPath('/api/users/me')).toBe('/account')
    expect(safeRedirectPath('/api?x=1')).toBe('/account')
    expect(safeRedirectPath('/apiary')).toBe('/apiary')
    expect(safeRedirectPath('/backend/x', '/', { apiPrefix: '/backend' })).toBe('/')
  })

  it('lets null disable only the sign-in rule', () => {
    expect(safeRedirectPath('/sign-in', '/', { signInPath: null })).toBe('/sign-in')
    expect(safeRedirectPath('/api/x', '/', { signInPath: null })).toBe('/')
  })

  it('keeps ordinary in-app paths byte for byte', () => {
    expect(safeRedirectPath('/account?tab=1&mode=edit')).toBe('/account?tab=1&mode=edit')
    expect(safeRedirectPath('/sign-in-authjs')).toBe('/sign-in-authjs')
  })
})

describe('safeRedirectPath dot-segment normalisation', () => {
  it('applies the API and sign-in rules after resolving dot segments', () => {
    for (const value of [
      '/x/../api/auth-link/session',
      '/./sign-in',
      '/%2e%2e/api/x',
      '/%2E%2E/api/x',
      '/./api/x',
      '/a/b/../../api',
      '/x/%2e%2e/sign-in?redirect=/account',
      '/sign-in/',
      '/%61pi/users/me',
      '/%73ign-in',
      '/.//evil.example.com',
      '/x/..//evil.example.com',
      '/%2F%2Fevil.example.com',
      '/%5Cevil.example.com',
      '/%E0%A4%A',
    ]) {
      expect(safeRedirectPath(value), value).toBe('/account')
    }
  })

  it('returns the normalised path with its query and hash', () => {
    expect(safeRedirectPath('/x/../account?tab=1#top')).toBe('/account?tab=1#top')
    expect(safeRedirectPath('/./dashboard')).toBe('/dashboard')
    expect(safeRedirectPath('/../../dashboard')).toBe('/dashboard')
  })
})

describe('safeRedirectPath properties', () => {
  const origin = 'https://app.example.com'
  const segment = fc.oneof(
    fc.constantFrom('.', '..', '%2e', '%2E%2e', 'api', 'sign-in', '', '%2f', '%5c', 'x', '%00'),
    fc.string({ maxLength: 6 })
  )
  const pathLike = fc.oneof(
    fc.array(segment, { maxLength: 6 }).map((parts) => `/${parts.join('/')}`),
    fc.string({ maxLength: 24 }),
    fc
      .tuple(fc.array(segment, { maxLength: 5 }), fc.string({ maxLength: 8 }))
      .map(([parts, tail]) => `/${parts.join('/')}?${tail}`)
  )

  function decodedPathname(path: string): string {
    const pathname = new URL(path, origin).pathname
    return new URL(decodeURIComponent(pathname), origin).pathname
  }

  it('always yields a same-origin path outside the API prefix and sign-in page', () => {
    fc.assert(
      fc.property(pathLike, (value) => {
        const result = safeRedirectPath(value, '/account')
        if (result === '/account') {
          return
        }
        expect(result.startsWith('/')).toBe(true)
        expect(result.startsWith('//')).toBe(false)
        const resolved = new URL(result, origin)
        expect(resolved.origin).toBe(origin)
        for (const pathname of [resolved.pathname, decodedPathname(result)]) {
          expect(pathname === '/api' || pathname.startsWith('/api/')).toBe(false)
          expect(pathname === '/sign-in' || pathname === '/sign-in/').toBe(false)
        }
        // Idempotent: a safe path stays put on a second pass.
        expect(safeRedirectPath(result, '/account')).toBe(result)
      }),
      { numRuns: 2000 }
    )
  })
})
