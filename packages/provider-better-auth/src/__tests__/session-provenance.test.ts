/**
 * Session provenance recording (issues #86, #110): the after-hook
 * relabels a session ONLY when its endpoint succeeded. A non-200
 * Response (verify-totp RETURNS a 401 for a wrong code), a thrown or
 * returned APIError, or an empty result must never write a method —
 * a wrong second factor relabelling a single-factor session as
 * `two-factor` would forge an MFA proof.
 *
 * The mocks follow Better Auth 1.7's real after-hook context: the
 * request cookie arrives on `ctx.headers` and is read through Better
 * Call's real `ctx.getSignedCookie` (createAuthMiddleware builds it;
 * there is no `ctx.context.request`), and the session the endpoint
 * authenticated is `ctx.context.session`. The real-engine walks in
 * `server-sessions-engine.test.ts` pin the same behavior end to end.
 */
import { APIError } from 'better-auth/api'
import { createHmac } from 'node:crypto'
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
const SECRET = 'provenance-unit-secret'

/** A session cookie pair signed exactly like Better Call's `signCookieValue`. */
function signed(token: string, secret = SECRET): string {
  const signature = createHmac('sha256', secret).update(token).digest('base64')
  return `${COOKIE}=${encodeURIComponent(`${token}.${signature}`)}`
}

type Overrides = {
  setCookies?: readonly string[]
  /** The request Cookie header (read through Better Call's real `ctx.getSignedCookie`). */
  cookie?: string
  /** The session BA resolved for the request (`ctx.context.session`). */
  resolved?: unknown
  secret?: unknown
  cookieName?: string | undefined
  updateSession?: unknown
}

function run(path: string, returned: unknown, overrides: Overrides = {}) {
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
    headers: new Headers(overrides.cookie === undefined ? {} : { cookie: overrides.cookie }),
    context: {
      returned,
      secret: 'secret' in overrides ? overrides.secret : SECRET,
      session: 'resolved' in overrides ? overrides.resolved : null,
      authCookies: {
        sessionToken: { name: 'cookieName' in overrides ? overrides.cookieName : COOKIE },
      },
      responseHeaders,
      internalAdapter: { updateSession },
    },
  }
  return { promise: afterHook().handler(ctx), updateSession }
}

/** `ctx.context.session` as BA's `getSessionFromCtx` sets it. */
function resolvedSession(token: string) {
  return { session: { id: `id-${token}`, token }, user: { id: 'u-1' } }
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
      cookie: signed('presented-token'),
      resolved: resolvedSession('presented-token'),
    })
    await promise
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('steps up the presented session BA authenticated (no Set-Cookie)', async () => {
    const { promise, updateSession } = run(
      '/two-factor/verify-totp',
      { token: 'presented-token' },
      {
        cookie: `other=1; ${signed('presented-token')}`,
        resolved: resolvedSession('presented-token'),
      }
    )
    await promise
    expect(updateSession).toHaveBeenCalledWith('presented-token', {
      authenticationMethod: 'two-factor',
    })
  })

  it.each([
    ['the cookie names a different session than BA resolved', signed('other'), 'resolved-token'],
    [
      'two session cookies are presented and the first is not the resolved one',
      `${signed('other')}; ${signed('resolved-token')}`,
      'resolved-token',
    ],
    [
      'the cookie signature does not verify',
      signed('resolved-token', 'wrong-secret'),
      'resolved-token',
    ],
    ['the cookie is unsigned', `${COOKIE}=resolved-token`, 'resolved-token'],
    ['no session cookie is presented', 'unrelated=1', 'resolved-token'],
    ['BA resolved no session (sign-in challenge path)', signed('presented-token'), null],
  ] as const)(
    'relabels nothing on a second-factor path when %s',
    async (_label, cookie, resolved) => {
      const { promise, updateSession } = run(
        '/two-factor/verify-totp',
        { token: 'x' },
        {
          cookie,
          resolved: resolved === null ? null : resolvedSession(resolved),
        }
      )
      await promise
      expect(updateSession).not.toHaveBeenCalled()
    }
  )

  it.each([
    ['no secret', { secret: undefined }],
    ['an empty secret', { secret: '' }],
    ['a malformed resolved session', { resolved: { session: { token: 42 } } }],
    ['a resolved session without a row', { resolved: { user: {} } }],
    ['an empty resolved token', { resolved: resolvedSession('') }],
  ] as const)('fails closed on a step-up with %s', async (_label, extra) => {
    const { promise, updateSession } = run(
      '/two-factor/verify-totp',
      { token: 'x' },
      { cookie: signed('presented-token'), resolved: resolvedSession('presented-token'), ...extra }
    )
    await promise
    expect(updateSession).not.toHaveBeenCalled()
  })

  it("prefers the response's own session cookie (fresh sign-in)", async () => {
    const { promise, updateSession } = run(
      '/sign-in/email',
      { token: 'x' },
      {
        setCookies: [`unrelated=1; Path=/`, `${COOKIE}=fresh-token.sig; Path=/; HttpOnly`],
        cookie: signed('stale-token'),
        resolved: resolvedSession('stale-token'),
      }
    )
    await promise
    expect(updateSession).toHaveBeenCalledWith('fresh-token', { authenticationMethod: 'password' })
  })

  it("labels the rotated session on a second-factor path (enrollment's new cookie)", async () => {
    const { promise, updateSession } = run(
      '/two-factor/verify-totp',
      { token: 'old' },
      {
        setCookies: [`${COOKIE}=rotated-token.sig; Path=/`],
        cookie: signed('old'),
        resolved: resolvedSession('old'),
      }
    )
    await promise
    expect(updateSession).toHaveBeenCalledTimes(1)
    expect(updateSession).toHaveBeenCalledWith('rotated-token', {
      authenticationMethod: 'two-factor',
    })
  })

  it('records nothing when the response EXPIRES the session cookie', async () => {
    const { promise, updateSession } = run(
      '/two-factor/verify-totp',
      { ok: true },
      {
        setCookies: [`${COOKIE}=; Max-Age=0; Path=/`],
        cookie: signed('presented-token'),
        resolved: resolvedSession('presented-token'),
      }
    )
    await promise
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('never relabels a PRESENTED session on a first-factor path', async () => {
    // A first-factor endpoint that set no session cookie created
    // nothing to record; the presented session keeps its label.
    const { promise, updateSession } = run(
      '/sign-in/email',
      { twoFactorRedirect: true },
      { cookie: signed('presented-token'), resolved: resolvedSession('presented-token') }
    )
    await promise
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('records nothing when the token surface cannot be resolved (fail closed)', async () => {
    for (const overrides of [
      { cookieName: undefined },
      { cookieName: '' },
      { updateSession: undefined },
      // No session cookie anywhere.
      {},
    ] as const) {
      const { promise, updateSession } = run(
        '/sign-in/email',
        { ok: true },
        { setCookies: [`${COOKIE}=fresh.sig`], ...overrides }
      )
      await promise
      if (typeof updateSession === 'function' && 'cookieName' in overrides) {
        expect(updateSession).not.toHaveBeenCalled()
      }
    }
    const { promise, updateSession } = run('/sign-in/email', { ok: true })
    await promise
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('accepts an unsigned Set-Cookie value as the raw token', async () => {
    const { promise, updateSession } = run('/magic-link/verify', new Response('{}'), {
      setCookies: [`${COOKIE}=unsigned-token; Path=/`],
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
