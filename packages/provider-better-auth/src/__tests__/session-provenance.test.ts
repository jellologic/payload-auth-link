/**
 * Session provenance recording (issue #86): the after-hook relabels
 * the presented session ONLY when its endpoint succeeded. A non-200
 * Response (verify-totp RETURNS a 401 for a wrong code), a thrown or
 * returned APIError, or an empty result must never write a method —
 * a wrong second factor relabelling a single-factor session as
 * `two-factor` would forge an MFA proof.
 */
import { APIError } from 'better-auth/api'
import { describe, expect, it, vi } from 'vitest'
import { sessionProvenancePlugin } from '../session-provenance.js'

type AfterHook = {
  readonly matcher: (ctx: { path?: string }) => boolean
  readonly handler: (ctx: Record<string, unknown>) => Promise<unknown>
}

function afterHook(): AfterHook {
  const hook = sessionProvenancePlugin.hooks?.after?.[0] as AfterHook | undefined
  if (hook === undefined) {
    throw new Error('provenance after-hook missing')
  }
  return hook
}

const COOKIE = 'better-auth.session_token'

function run(
  path: string,
  returned: unknown,
  overrides: {
    setCookies?: readonly string[]
    requestCookie?: string
    cookieName?: string | undefined
    updateSession?: unknown
  } = {}
) {
  const updateSession =
    'updateSession' in overrides
      ? overrides.updateSession
      : vi.fn<(token: string, data: Record<string, unknown>) => Promise<null>>(() =>
          Promise.resolve(null)
        )
  const responseHeaders = new Headers()
  for (const entry of overrides.setCookies ?? []) {
    responseHeaders.append('set-cookie', entry)
  }
  const ctx = {
    path,
    headers: new Headers(),
    context: {
      returned,
      authCookies: {
        sessionToken: { name: 'cookieName' in overrides ? overrides.cookieName : COOKIE },
      },
      responseHeaders,
      request: { headers: new Headers({ cookie: overrides.requestCookie ?? '' }) },
      internalAdapter: { updateSession },
    },
  }
  return { promise: afterHook().handler(ctx), updateSession }
}

describe('session provenance after-hook', () => {
  it('matches only the method-bearing endpoints', () => {
    const { matcher } = afterHook()
    expect(matcher({ path: '/sign-in/email' })).toBe(true)
    expect(matcher({ path: '/two-factor/verify-totp' })).toBe(true)
    expect(matcher({ path: '/callback/github' })).toBe(true)
    expect(matcher({ path: '/oauth2/callback/okta' })).toBe(true)
    expect(matcher({ path: '/magic-link/verify' })).toBe(true)
    expect(matcher({ path: '/email-otp/sign-in-email-otp' })).toBe(true)
    expect(matcher({ path: '/passkey/authenticate' })).toBe(true)
    expect(matcher({ path: '/sign-up/email' })).toBe(false)
    expect(matcher({})).toBe(false)
  })

  it.each([
    ['401 Response (wrong TOTP code)', new Response('{}', { status: 401 })],
    ['302 Response', new Response(null, { status: 302 })],
    ['500 Response', new Response('{}', { status: 500 })],
    ['returned APIError', new APIError('UNAUTHORIZED', { message: 'bad code' })],
    ['null result', null],
    ['undefined result', undefined],
  ])('a failed endpoint never relabels the session: %s', async (_label, returned) => {
    const { promise, updateSession } = run('/two-factor/verify-totp', returned, {
      requestCookie: `${COOKIE}=presented-token.sig`,
    })
    await promise
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('records the method on a 200 Response, from the request cookie', async () => {
    const { promise, updateSession } = run(
      '/two-factor/verify-totp',
      new Response('{}', { status: 200 }),
      { requestCookie: `other=1; ${COOKIE}=presented-token.sig` }
    )
    await promise
    expect(updateSession).toHaveBeenCalledWith('presented-token', {
      authenticationMethod: 'two-factor',
    })
  })

  it("prefers the response's own session cookie (fresh sign-in)", async () => {
    const { promise, updateSession } = run(
      '/sign-in/email',
      { token: 'x' },
      {
        setCookies: [`unrelated=1; Path=/`, `${COOKIE}=fresh-token.sig; Path=/; HttpOnly`],
        requestCookie: `${COOKIE}=stale-token.sig`,
      }
    )
    await promise
    expect(updateSession).toHaveBeenCalledWith('fresh-token', { authenticationMethod: 'password' })
  })

  it('records nothing when the token surface cannot be resolved (fail closed)', async () => {
    for (const overrides of [
      { cookieName: undefined },
      { cookieName: '' },
      { updateSession: undefined },
      // No session cookie anywhere.
      {},
      // An empty cookie value.
      { setCookies: [`${COOKIE}=; Path=/`] },
    ]) {
      const { promise, updateSession } = run('/sign-in/email', { ok: true }, overrides)
      await promise
      if (typeof updateSession === 'function') {
        expect(updateSession).not.toHaveBeenCalled()
      }
    }
  })

  it('accepts an unsigned cookie value as the raw token', async () => {
    const { promise, updateSession } = run('/magic-link/verify', new Response('{}'), {
      requestCookie: `${COOKIE}=unsigned-token`,
    })
    await promise
    expect(updateSession).toHaveBeenCalledWith('unsigned-token', {
      authenticationMethod: 'magic-link',
    })
  })

  it('records nothing when the request carries no headers at all', async () => {
    const updateSession = vi.fn()
    await afterHook().handler({
      path: '/sign-in/email',
      context: {
        returned: { ok: true },
        authCookies: { sessionToken: { name: COOKIE } },
        internalAdapter: { updateSession },
      },
    })
    expect(updateSession).not.toHaveBeenCalled()
  })
})
