import { NextRequest } from 'next/server'
import { describe, expect, it } from 'vitest'
import { checkAuthCookies, createAuthMiddleware } from '../middleware.js'

const cookieNames = ['better-auth.session_token']

function request(path: string, cookie?: string): NextRequest {
  return new NextRequest(
    new Request(`http://localhost:3000${path}`, cookie ? { headers: { cookie } } : undefined)
  )
}

function isPassThrough(response: Response): boolean {
  return response.headers.get('location') === null
}

describe('checkAuthCookies (composable form)', () => {
  it('returns the 303 redirect for anonymous private paths and null for pass-through', () => {
    const bounced = checkAuthCookies(request('/private'), { sessionCookieNames: cookieNames })
    expect(bounced?.status).toBe(303)
    expect(bounced?.headers.get('location')).toContain('/sign-in')
    expect(
      checkAuthCookies(request('/private', 'better-auth.session_token=abc'), {
        sessionCookieNames: cookieNames,
      })
    ).toBeNull()
    expect(
      checkAuthCookies(request('/'), {
        sessionCookieNames: cookieNames,
        publicPaths: ['/'],
      })
    ).toBeNull()
  })

  it('composes with an existing pipeline via ??', () => {
    const next = (candidate: NextRequest): string => {
      return (
        checkAuthCookies(candidate, {
          sessionCookieNames: cookieNames,
          publicPaths: ['/'],
        })?.status.toString() ?? 'passed'
      )
    }
    expect(next(request('/private'))).toBe('303')
    expect(next(request('/'))).toBe('passed')
  })
})

describe('createAuthMiddleware', () => {
  it('passes public string paths without cookies', () => {
    const middleware = createAuthMiddleware({
      sessionCookieNames: cookieNames,
      publicPaths: ['/', '/about'],
    })
    expect(isPassThrough(middleware(request('/')))).toBe(true)
    expect(isPassThrough(middleware(request('/about')))).toBe(true)
    expect(isPassThrough(middleware(request('/private')))).toBe(false)
  })

  it('matches public regexes against the pathname', () => {
    const middleware = createAuthMiddleware({
      sessionCookieNames: cookieNames,
      publicPaths: [/^\/docs(\/|$)/],
    })
    expect(isPassThrough(middleware(request('/docs/guide')))).toBe(true)
    expect(isPassThrough(middleware(request('/private')))).toBe(false)
  })

  it('keeps the sign-in page public (no redirect loops)', () => {
    const middleware = createAuthMiddleware({ sessionCookieNames: cookieNames })
    expect(isPassThrough(middleware(request('/sign-in')))).toBe(true)
  })

  it('passes requests carrying any session cookie', () => {
    const middleware = createAuthMiddleware({ sessionCookieNames: cookieNames })
    expect(
      isPassThrough(middleware(request('/private', 'other=1; better-auth.session_token=abc')))
    ).toBe(true)
    expect(isPassThrough(middleware(request('/private', 'other=1')))).toBe(false)
  })

  it('redirects anonymous traffic with the intercepted path', () => {
    const middleware = createAuthMiddleware({ sessionCookieNames: cookieNames })
    const response = middleware(request('/private?tab=1'))
    expect(response.status).toBe(303)
    const location = response.headers.get('location')
    expect(location).toBe('http://localhost:3000/sign-in?redirect=%2Fprivate%3Ftab%3D1')
  })

  it('bounces POSTs as 303 so they become GETs to sign-in', () => {
    const middleware = createAuthMiddleware({ sessionCookieNames: cookieNames })
    const post = new NextRequest(new Request('http://localhost:3000/private', { method: 'POST' }))
    const response = middleware(post)
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe(
      'http://localhost:3000/sign-in?redirect=%2Fprivate'
    )
  })

  it('honors custom sign-in path and redirect param', () => {
    const middleware = createAuthMiddleware({
      sessionCookieNames: cookieNames,
      signInPath: '/login',
      redirectParam: 'next',
    })
    expect(isPassThrough(middleware(request('/login')))).toBe(true)
    const response = middleware(request('/private'))
    expect(response.headers.get('location')).toBe('http://localhost:3000/login?next=%2Fprivate')
  })

  it('fails closed with empty cookie names', () => {
    const middleware = createAuthMiddleware({ sessionCookieNames: [] })
    expect(isPassThrough(middleware(request('/private', 'a=b')))).toBe(false)
  })
})
