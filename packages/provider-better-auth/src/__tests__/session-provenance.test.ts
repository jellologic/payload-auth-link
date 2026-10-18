/**
 * Session provenance recording (issues #86, #110,
 * GHSA-38wx-69j6-cgm7): the after-hook relabels a session ONLY when
 * its endpoint succeeded. A non-200 Response, a thrown or returned
 * APIError, or an empty result must never write a method — a wrong
 * second factor relabelling a single-factor session as `two-factor`
 * would forge an MFA proof. On `/two-factor/verify*` the before-hook's
 * assessment (step-up.ts) additionally decides whether a correct code
 * may relabel at all, and the lockout budget is spent or reset.
 *
 * The mocks follow Better Auth 1.7's real hook context: the request
 * cookie arrives on `ctx.headers` and is read through Better Call's
 * real `ctx.getSignedCookie` (createAuthMiddleware builds it; there is
 * no `ctx.context.request`), and the session the endpoint
 * authenticated is `ctx.context.session` (which BA's
 * `getSessionFromCtx` also returns as-is when set, so the before-hook
 * resolves the same mocked session). The real-engine walks in
 * `server-sessions-engine.test.ts` and `mfa-step-up-engine.test.ts`
 * pin the same behavior end to end.
 */
import { APIError } from 'better-auth/api'
import type { BetterAuthPlugin } from 'better-auth'
import { createHmac } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { createSessionProvenancePlugin, sessionProvenancePlugin } from '../session-provenance.js'

type Hook = {
  readonly matcher: (ctx: { path?: string }) => boolean
  readonly handler: (ctx: Record<string, unknown>) => Promise<unknown>
}

function hookOf(plugin: BetterAuthPlugin, phase: 'before' | 'after'): Hook {
  const hook = plugin.hooks?.[phase]?.[0] as Hook | undefined
  if (hook === undefined) {
    throw new Error(`provenance ${phase}-hook missing`)
  }
  return hook
}

function afterHook(): Hook {
  return hookOf(sessionProvenancePlugin, 'after')
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
  /** The FRESH session row's recorded first factor (before-hook read). */
  firstFactor?: string | null
  /** The user's `twoFactorEnabled` before the request. */
  twoFactorEnabled?: boolean
  /** The `twoFactor` row before the request (`null`: none). */
  row?: Record<string, unknown> | null
  /** The installed two-factor plugin's options. */
  twoFactorOptions?: Record<string, unknown>
  plugin?: BetterAuthPlugin
  incrementOne?: unknown
}

async function run(path: string, returned: unknown, overrides: Overrides = {}) {
  const plugin = overrides.plugin ?? sessionProvenancePlugin
  const updateSession =
    'updateSession' in overrides
      ? overrides.updateSession
      : vi.fn<(token: string, data: Record<string, unknown>) => Promise<null>>(() =>
          Promise.resolve(null)
        )
  const incrementOne =
    'incrementOne' in overrides
      ? overrides.incrementOne
      : vi.fn<(query: Record<string, unknown>) => Promise<unknown>>(() =>
          Promise.resolve({ failedVerificationCount: 1 })
        )
  const update = vi.fn<(query: Record<string, unknown>) => Promise<unknown>>(() =>
    Promise.resolve(null)
  )
  const resolved = 'resolved' in overrides ? overrides.resolved : null
  const responseHeaders = new Headers()
  for (const entry of overrides.setCookies ?? []) {
    responseHeaders.append('set-cookie', entry)
  }
  const ctx: Record<string, unknown> & { context: Record<string, unknown> } = {
    path,
    headers: new Headers(overrides.cookie === undefined ? {} : { cookie: overrides.cookie }),
    context: {
      returned,
      secret: 'secret' in overrides ? overrides.secret : SECRET,
      session: resolved,
      authCookies: {
        sessionToken: { name: 'cookieName' in overrides ? overrides.cookieName : COOKIE },
      },
      responseHeaders,
      getPlugin: (id: string) =>
        id === 'two-factor' ? { options: overrides.twoFactorOptions ?? {} } : null,
      internalAdapter: {
        updateSession,
        findSession: (token: string) =>
          Promise.resolve({
            session: {
              token,
              authenticationMethod: 'firstFactor' in overrides ? overrides.firstFactor : 'password',
            },
            user: { id: 'u-1', twoFactorEnabled: overrides.twoFactorEnabled ?? true },
          }),
      },
      adapter: {
        findOne: () =>
          Promise.resolve('row' in overrides ? overrides.row : { id: 'tf-1', verified: true }),
        incrementOne,
        update,
      },
    },
  }
  const before = hookOf(plugin, 'before')
  if (before.matcher({ path })) {
    const result = (await before.handler(ctx)) as { context: Record<string, unknown> }
    // Better Auth merges the returned context into the endpoint context.
    Object.assign(ctx, result.context)
  }
  await hookOf(plugin, 'after').handler(ctx)
  return { updateSession, incrementOne, update }
}

/** `ctx.context.session` as BA's `getSessionFromCtx` sets it. */
function resolvedSession(token: string) {
  return { session: { id: `id-${token}`, token }, user: { id: 'u-1' } }
}

/** A step-up request on the presented session `token`. */
function stepUp(token: string): Pick<Overrides, 'cookie' | 'resolved'> {
  return { cookie: signed(token), resolved: resolvedSession(token) }
}

describe('session provenance after-hook', () => {
  it('matches only the method-bearing endpoints', () => {
    const { matcher } = afterHook()
    expect(matcher({ path: '/sign-in/email' })).toBe(true)
    expect(matcher({ path: '/two-factor/verify-totp' })).toBe(true)
    expect(matcher({ path: '/callback/github' })).toBe(true)
    expect(matcher({ path: '/oauth2/callback/okta' })).toBe(true)
    expect(matcher({ path: '/magic-link/verify' })).toBe(true)
    expect(matcher({ path: '/sign-in/email-otp' })).toBe(true)
    expect(matcher({ path: '/passkey/authenticate' })).toBe(true)
    expect(matcher({ path: '/sign-up/email' })).toBe(false)
    expect(matcher({})).toBe(false)
  })

  it('the before-hook matches only the second-factor verifications', () => {
    const { matcher } = hookOf(sessionProvenancePlugin, 'before')
    expect(matcher({ path: '/two-factor/verify-totp' })).toBe(true)
    expect(matcher({ path: '/two-factor/verify-otp' })).toBe(true)
    expect(matcher({ path: '/two-factor/verify-backup-code' })).toBe(true)
    expect(matcher({ path: '/two-factor/enable' })).toBe(false)
    expect(matcher({ path: '/sign-in/email' })).toBe(false)
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
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      returned,
      stepUp('presented-token')
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('steps up the presented session BA authenticated (no Set-Cookie)', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'presented-token' },
      {
        cookie: `other=1; ${signed('presented-token')}`,
        resolved: resolvedSession('presented-token'),
      }
    )
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
      const { updateSession } = await run(
        '/two-factor/verify-totp',
        { token: 'x' },
        {
          cookie,
          resolved: resolved === null ? null : resolvedSession(resolved),
        }
      )
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
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'x' },
      { ...stepUp('presented-token'), ...extra }
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it("prefers the response's own session cookie (fresh sign-in)", async () => {
    const { updateSession } = await run(
      '/sign-in/email',
      { token: 'x' },
      {
        setCookies: [`unrelated=1; Path=/`, `${COOKIE}=fresh-token.sig; Path=/; HttpOnly`],
        ...stepUp('stale-token'),
      }
    )
    expect(updateSession).toHaveBeenCalledWith('fresh-token', { authenticationMethod: 'password' })
  })

  it('labels the session a two-factor SIGN-IN issues', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'fresh' },
      { setCookies: [`${COOKIE}=fresh.sig; Path=/`], cookie: 'better-auth.two_factor=x' }
    )
    expect(updateSession).toHaveBeenCalledWith('fresh', { authenticationMethod: 'two-factor' })
  })

  it('a step-up that re-sets the SAME token (refresh) relabels it', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'presented-token' },
      { setCookies: [`${COOKIE}=presented-token.sig; Path=/`], ...stepUp('presented-token') }
    )
    expect(updateSession).toHaveBeenCalledWith('presented-token', {
      authenticationMethod: 'two-factor',
    })
  })

  it('a step-up that issues ANOTHER session relabels nothing', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'presented-token' },
      { setCookies: [`${COOKIE}=rotated-token.sig; Path=/`], ...stepUp('presented-token') }
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('an ENROLMENT confirmation (2FA off before the request) relabels nothing', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'old' },
      {
        setCookies: [`${COOKIE}=rotated-token.sig; Path=/`],
        ...stepUp('old'),
        twoFactorEnabled: false,
        row: { id: 'tf-1', verified: false },
      }
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it.each([
    ['an unconfirmed row', { id: 'tf-1', verified: false }],
    ['no row at all', null],
  ])('a TOTP / backup-code step-up proves nothing with %s', async (_label, row) => {
    for (const path of ['/two-factor/verify-totp', '/two-factor/verify-backup-code']) {
      const { updateSession } = await run(path, { token: 'p' }, { ...stepUp('p'), row })
      expect(updateSession).not.toHaveBeenCalled()
    }
  })

  it.each([
    ['magic-link', false],
    ['email-otp', false],
    ['oauth', false],
    [null, false],
    ['server-mint', false],
    ['password', true],
    ['passkey', true],
  ] as const)(
    'an OTP step-up after a %s first factor relabels: %s (default channel)',
    async (firstFactor, relabels) => {
      const { updateSession } = await run(
        '/two-factor/verify-otp',
        { token: 'p' },
        { ...stepUp('p'), firstFactor, row: null }
      )
      expect(updateSession).toHaveBeenCalledTimes(relabels ? 1 : 0)
    }
  )

  it('an OTP step-up relabels after any first factor when the channel is independent', async () => {
    const plugin = createSessionProvenancePlugin({ twoFactorOtpChannelIndependent: true })
    const { updateSession } = await run(
      '/two-factor/verify-otp',
      { token: 'p' },
      { ...stepUp('p'), firstFactor: 'magic-link', plugin }
    )
    expect(updateSession).toHaveBeenCalledWith('p', { authenticationMethod: 'two-factor' })
  })

  it('an OTP that turns 2FA ON (enrolment) relabels nothing, even after a password', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-otp',
      { token: 'p' },
      { ...stepUp('p'), twoFactorEnabled: false }
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('a second-factor path without this module’s assessment relabels nothing', async () => {
    const updateSession = vi.fn()
    const base = {
      path: '/two-factor/verify-totp',
      headers: new Headers({ cookie: signed('p') }),
      context: {
        returned: { token: 'p' },
        secret: SECRET,
        session: resolvedSession('p'),
        authCookies: { sessionToken: { name: COOKIE } },
        responseHeaders: new Headers(),
        internalAdapter: { updateSession },
      },
    }
    await afterHook().handler(base)
    // A look-alike planted on the context is not an issued assessment.
    await afterHook().handler({
      ...base,
      payloadAuthLinkSecondFactor: { kind: 'step-up', token: 'p', provesMfa: true },
    })
    await afterHook().handler({ ...base, payloadAuthLinkSecondFactor: 'step-up' })
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('records nothing when the response EXPIRES the session cookie', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { ok: true },
      { setCookies: [`${COOKIE}=; Max-Age=0; Path=/`], ...stepUp('presented-token') }
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('never relabels a PRESENTED session on a first-factor path', async () => {
    // A first-factor endpoint that set no session cookie created
    // nothing to record; the presented session keeps its label.
    const { updateSession } = await run(
      '/sign-in/email',
      { twoFactorRedirect: true },
      stepUp('presented-token')
    )
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('records nothing when the token surface cannot be resolved (fail closed)', async () => {
    for (const overrides of [
      { cookieName: undefined },
      { cookieName: '' },
      { updateSession: undefined },
    ] as const) {
      const { updateSession } = await run(
        '/sign-in/email',
        { ok: true },
        { setCookies: [`${COOKIE}=fresh.sig`], ...overrides }
      )
      if (typeof updateSession === 'function') {
        expect(updateSession).not.toHaveBeenCalled()
      }
    }
    const { updateSession } = await run('/sign-in/email', { ok: true })
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('accepts an unsigned Set-Cookie value as the raw token', async () => {
    const { updateSession } = await run('/magic-link/verify', new Response('{}'), {
      setCookies: [`${COOKIE}=unsigned-token; Path=/`],
    })
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

describe('step-up lockout (GHSA-38wx-69j6-cgm7)', () => {
  const wrongCode = APIError.from('UNAUTHORIZED', { code: 'INVALID_CODE', message: 'Invalid code' })

  it('refuses a step-up while the account is locked, before the endpoint runs', async () => {
    const locked = run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        row: { id: 'tf-1', verified: true, lockedUntil: new Date(Date.now() + 60_000) },
      }
    )
    await expect(locked).rejects.toMatchObject({
      statusCode: 429,
      body: { code: 'ACCOUNT_TEMPORARILY_LOCKED' },
    })
  })

  it('reads a serialized lockedUntil too', async () => {
    const locked = run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        row: { id: 'tf-1', lockedUntil: new Date(Date.now() + 60_000).toISOString() },
      }
    )
    await expect(locked).rejects.toMatchObject({ statusCode: 429 })
  })

  it('ignores the lock when Better Auth lockout is disabled', async () => {
    const { updateSession, incrementOne } = await run('/two-factor/verify-totp', wrongCode, {
      ...stepUp('p'),
      row: { id: 'tf-1', verified: true, lockedUntil: new Date(Date.now() + 60_000) },
      twoFactorOptions: { accountLockout: { enabled: false } },
    })
    expect(updateSession).not.toHaveBeenCalled()
    expect(incrementOne).not.toHaveBeenCalled()
  })

  it('clears an expired lock with a guarded write, then proceeds', async () => {
    const { incrementOne, updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        row: { id: 'tf-1', verified: true, lockedUntil: new Date(Date.now() - 1000) },
      }
    )
    expect(incrementOne).toHaveBeenCalledWith(
      expect.objectContaining({
        set: { failedVerificationCount: 0, lockedUntil: null },
        where: expect.arrayContaining([
          expect.objectContaining({ field: 'lockedUntil', operator: 'lte' }),
        ]) as unknown,
      })
    )
    expect(updateSession).toHaveBeenCalled()
  })

  it.each([
    ['an unparseable date', 'not-a-date'],
    ['a non-date value', true],
  ])('treats %s as no lock', async (_label, lockedUntil) => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        row: { id: 'tf-1', verified: true, lockedUntil },
      }
    )
    expect(updateSession).toHaveBeenCalled()
  })

  it('a wrong step-up code spends the budget; the last one locks', async () => {
    const counted = vi.fn<(query: Record<string, unknown>) => Promise<unknown>>(() =>
      Promise.resolve({ failedVerificationCount: 1 })
    )
    await run('/two-factor/verify-totp', wrongCode, { ...stepUp('p'), incrementOne: counted })
    expect(counted).toHaveBeenCalledTimes(1)
    expect(counted).toHaveBeenCalledWith(
      expect.objectContaining({ increment: { failedVerificationCount: 1 } })
    )

    const spent = vi.fn<(query: Record<string, unknown>) => Promise<unknown>>(() =>
      Promise.resolve({ failedVerificationCount: 3 })
    )
    await run('/two-factor/verify-backup-code', wrongCode, {
      ...stepUp('p'),
      incrementOne: spent,
      twoFactorOptions: { accountLockout: { maxFailedAttempts: 3, durationSeconds: 60 } },
    })
    expect(spent).toHaveBeenCalledTimes(2)
    expect(spent).toHaveBeenLastCalledWith(
      expect.objectContaining({ set: { lockedUntil: expect.any(Date) as unknown } })
    )
  })

  it('a correct step-up resets the budget', async () => {
    const { update } = await run('/two-factor/verify-totp', { token: 'p' }, stepUp('p'))
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({ update: { failedVerificationCount: 0, lockedUntil: null } })
    )
  })

  it.each([
    ['an expired OTP', APIError.from('BAD_REQUEST', { code: 'OTP_HAS_EXPIRED', message: 'x' })],
    ['an APIError without a body code', new APIError('UNAUTHORIZED')],
    ['a non-200 Response', new Response(null, { status: 401 })],
  ])('%s neither spends nor resets the budget', async (_label, returned) => {
    const { incrementOne, update } = await run('/two-factor/verify-totp', returned, stepUp('p'))
    expect(incrementOne).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
  })

  it('keeps no budget without a twoFactor row (OTP-only enrolment, as Better Auth)', async () => {
    const { incrementOne, update } = await run('/two-factor/verify-otp', wrongCode, {
      ...stepUp('p'),
      row: null,
    })
    expect(incrementOne).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
  })

  it('never counts on the sign-in path (Better Auth counts there itself)', async () => {
    const { incrementOne } = await run('/two-factor/verify-totp', wrongCode, {
      cookie: 'better-auth.two_factor=x',
    })
    expect(incrementOne).not.toHaveBeenCalled()
  })

  it('logs and swallows a failed counter write', async () => {
    const error = vi.fn()
    const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error, child: vi.fn() }
    const plugin = createSessionProvenancePlugin({ logger })
    // A non-Error rejection is logged without leaking its value.
    await run('/two-factor/verify-totp', wrongCode, {
      ...stepUp('p'),
      plugin,
      incrementOne: () => Promise.reject(new Error('db down')),
    })
    await run('/two-factor/verify-totp', wrongCode, {
      ...stepUp('p'),
      plugin,
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- the case under test
      incrementOne: () => Promise.reject('opaque'),
    })
    expect(error).toHaveBeenCalledWith(
      'better-auth two-factor step-up: failure counter write failed',
      expect.objectContaining({ userId: 'u-1', outcome: 'failed-guess', cause: 'db down' })
    )
    expect(error).toHaveBeenCalledWith(
      'better-auth two-factor step-up: failure counter write failed',
      expect.objectContaining({ cause: 'unknown' })
    )
  })
})
