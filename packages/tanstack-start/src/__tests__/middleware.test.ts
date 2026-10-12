import { describe, expect, it } from 'vitest'
import { decideAuthRedirect } from '../index.js'
import { createAuthRequestMiddleware, type AuthRequestMiddlewareOptions } from '../middleware.js'

// Glue proof: the bounce matrix lives in `@payload-auth-link/web`
// (unit-tested there); this suite pins that the Start adapter exposes
// the shared decision and that it bounces anonymous traffic. The
// `createMiddleware` wrapper itself needs the Start runtime and is
// covered by e2e.
describe('decideAuthRedirect (tanstack-start export)', () => {
  it('passes public paths and bounces anonymous traffic', () => {
    const options = { sessionCookieNames: ['better-auth.session_token'], publicPaths: ['/'] }
    expect(decideAuthRedirect(new Request('http://localhost:3200/'), options)).toBeNull()
    expect(
      decideAuthRedirect(new Request('http://localhost:3200/private'), options)?.toString()
    ).toBe('http://localhost:3200/sign-in?redirect=%2Fprivate')
  })
})

/** Minimal server-fn context: our wrapper only uses `request` and `next`. */
type ServerFnContext = {
  readonly request: Request
  readonly next: () => Promise<Response>
}

/**
 * Invoke the registered Start server fn directly. `createMiddleware`
 * stores it on the middleware's `options.server` (the shape the Start
 * runtime itself reads), so this harness executes the real wrapper —
 * decision, status, and exemption — without the framework.
 */
async function runServerFn(
  options: AuthRequestMiddlewareOptions,
  request: Request
): Promise<{ response: Response; passedThrough: boolean }> {
  const middleware = createAuthRequestMiddleware(options) as unknown as {
    readonly options: {
      readonly server: (context: ServerFnContext) => Response | Promise<Response>
    }
  }
  let passedThrough = false
  const response = await middleware.options.server({
    request,
    next: () => {
      passedThrough = true
      return Promise.resolve(new Response('pass-through'))
    },
  })
  return { response, passedThrough }
}

const cookieNames = ['better-auth.session_token']

describe('createAuthRequestMiddleware', () => {
  it('bounces anonymous traffic as 303 so it becomes a GET to sign-in', async () => {
    const { response, passedThrough } = await runServerFn(
      { sessionCookieNames: cookieNames },
      new Request('http://localhost:3200/private?tab=1', { method: 'POST' })
    )
    expect(passedThrough).toBe(false)
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe(
      'http://localhost:3200/sign-in?redirect=%2Fprivate%3Ftab%3D1'
    )
  })

  it('passes requests carrying any session cookie', async () => {
    const { passedThrough } = await runServerFn(
      { sessionCookieNames: cookieNames },
      new Request('http://localhost:3200/private', {
        headers: { cookie: 'better-auth.session_token=abc' },
      })
    )
    expect(passedThrough).toBe(true)
  })

  it('exempts /_serverFn/ by default without a publicPaths entry', async () => {
    const { response, passedThrough } = await runServerFn(
      { sessionCookieNames: cookieNames },
      new Request('http://localhost:3200/_serverFn/x', { method: 'POST' })
    )
    expect(passedThrough).toBe(true)
    expect(response.status).toBe(200)
  })

  it('bounces /_serverFn/ when the exemption is opted out', async () => {
    const { response, passedThrough } = await runServerFn(
      { sessionCookieNames: cookieNames, bounceServerFunctions: true },
      new Request('http://localhost:3200/_serverFn/x', { method: 'POST' })
    )
    expect(passedThrough).toBe(false)
    expect(response.status).toBe(303)
  })
})
