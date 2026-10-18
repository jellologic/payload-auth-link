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
function signed(token: string, secret = SECRET, name = COOKIE): string {
  const signature = createHmac('sha256', secret).update(token).digest('base64')
  return `${name}=${encodeURIComponent(`${token}.${signature}`)}`
}

/** Better Auth's signed two-factor challenge cookie. */
const CHALLENGE_COOKIE = 'better-auth.two_factor'

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
  update?: unknown
  /** The issuance marker rows (`findMany` on `verification`); default none. */
  markers?: readonly Record<string, unknown>[]
  /** The fresh session row's `createdAt`. */
  createdAt?: unknown
  /** Live attempt rows `count` returns (users without a row). */
  liveAttempts?: unknown
  /** What `create` returns. */
  created?: unknown
  /** Replaces the `findOne` mock. */
  findOne?: Op
  /** The user id the challenge cookie's verification row names. */
  challengeUser?: unknown
  /** Replaces BA's `createAuthCookie`. */
  createAuthCookie?: unknown
}

type Op = (query: Record<string, unknown>) => Promise<unknown>

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
      : vi.fn<Op>(() => Promise.resolve({ failedVerificationCount: 1 }))
  const update = 'update' in overrides ? overrides.update : vi.fn<Op>(() => Promise.resolve(null))
  const findMany = vi.fn<Op>(() => Promise.resolve(overrides.markers ?? []))
  const create = vi.fn<Op>(() =>
    Promise.resolve('created' in overrides ? overrides.created : { id: 'v-1' })
  )
  const count = vi.fn<Op>(() =>
    Promise.resolve('liveAttempts' in overrides ? overrides.liveAttempts : 1)
  )
  const remove = vi.fn<Op>(() => Promise.resolve(null))
  const deleteMany = vi.fn<Op>(() => Promise.resolve(0))
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
      createAuthCookie:
        'createAuthCookie' in overrides
          ? overrides.createAuthCookie
          : (name: string) => ({ name: `better-auth.${name}` }),
      internalAdapter: {
        updateSession,
        findVerificationValue: () =>
          Promise.resolve(
            'challengeUser' in overrides ? { value: overrides.challengeUser } : { value: 'u-1' }
          ),
        findSession: (token: string) =>
          Promise.resolve({
            session: {
              token,
              authenticationMethod: 'firstFactor' in overrides ? overrides.firstFactor : 'password',
              createdAt: 'createdAt' in overrides ? overrides.createdAt : new Date(),
            },
            user: { id: 'u-1', twoFactorEnabled: overrides.twoFactorEnabled ?? true },
          }),
      },
      adapter: {
        findOne:
          overrides.findOne ??
          (() =>
            Promise.resolve('row' in overrides ? overrides.row : { id: 'tf-1', verified: true })),
        findMany,
        create,
        count,
        delete: remove,
        deleteMany,
        incrementOne,
        update,
      },
    },
  }
  for (const before of plugin.hooks?.before ?? []) {
    if (before.matcher(ctx as unknown as Parameters<typeof before.matcher>[0])) {
      const result = (await (before as unknown as Hook).handler(ctx)) as
        { context: Record<string, unknown> } | undefined
      // Better Auth merges the returned context into the endpoint context.
      Object.assign(ctx, result?.context)
    }
  }
  for (const after of plugin.hooks?.after ?? []) {
    if (after.matcher(ctx as unknown as Parameters<typeof after.matcher>[0])) {
      await (after as unknown as Hook).handler(ctx)
    }
  }
  return { updateSession, incrementOne, update, findMany, create, count, remove, deleteMany }
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
    'magic-link',
    'email-otp',
    'oauth',
    null,
    'server-mint',
    'password',
    'passkey',
  ] as const)(
    'an OTP step-up after a %s first factor relabels nothing (default channel)',
    async (firstFactor) => {
      // GHSA-xgx5-2cj5-x548: the inbox that receives the OTP can also
      // reset the password, so not even a password session qualifies.
      const { updateSession } = await run(
        '/two-factor/verify-otp',
        { token: 'p' },
        { ...stepUp('p'), firstFactor, row: null }
      )
      expect(updateSession).not.toHaveBeenCalled()
    }
  )

  it.each([
    ['/two-factor/verify-otp', false, 'password'],
    ['/two-factor/verify-otp', true, 'two-factor'],
    ['/two-factor/verify-totp', false, 'two-factor'],
    ['/two-factor/verify-backup-code', false, 'two-factor'],
  ] as const)(
    'a sign-in completed on %s (independent channel: %s) is labelled %s',
    async (path, twoFactorOtpChannelIndependent, method) => {
      const plugin = createSessionProvenancePlugin({ twoFactorOtpChannelIndependent })
      const { updateSession } = await run(
        path,
        { token: 'fresh' },
        { setCookies: [`${COOKIE}=fresh.sig; Path=/`], cookie: 'better-auth.two_factor=x', plugin }
      )
      expect(updateSession).toHaveBeenCalledWith('fresh', { authenticationMethod: method })
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

  it('ignores a path outside the method table even when invoked directly', async () => {
    const updateSession = vi.fn()
    await afterHook().handler({
      path: '/two-factor/enable',
      context: {
        returned: { ok: true },
        authCookies: { sessionToken: { name: COOKIE } },
        responseHeaders: new Headers({ 'set-cookie': `${COOKIE}=fresh.sig` }),
        internalAdapter: { updateSession },
      },
    })
    expect(updateSession).not.toHaveBeenCalled()
  })

  it('a sign-in with a malformed resolved session row still records the issued session', async () => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'fresh' },
      {
        setCookies: [`${COOKIE}=fresh.sig; Path=/`],
        cookie: 'better-auth.two_factor=x',
        resolved: { session: 'odd' },
      }
    )
    expect(updateSession).toHaveBeenCalledWith('fresh', { authenticationMethod: 'two-factor' })
  })

  it('a step-up whose resolved session is gone by the after-hook relabels nothing', async () => {
    const updateSession = vi.fn(() => Promise.resolve(null))
    const ctx: Record<string, unknown> & { context: Record<string, unknown> } = {
      path: '/two-factor/verify-totp',
      headers: new Headers({ cookie: signed('p') }),
      context: {
        returned: { token: 'p' },
        secret: SECRET,
        session: resolvedSession('p'),
        authCookies: { sessionToken: { name: COOKIE } },
        responseHeaders: new Headers(),
        internalAdapter: {
          updateSession,
          findSession: () =>
            Promise.resolve({
              session: { token: 'p', createdAt: new Date() },
              user: { id: 'u-1', twoFactorEnabled: true },
            }),
        },
        adapter: {
          findOne: () => Promise.resolve({ id: 'tf-1', verified: true }),
          findMany: () => Promise.resolve([]),
          incrementOne: () => Promise.resolve({ failedVerificationCount: 1 }),
          update: () => Promise.resolve(null),
        },
      },
    }
    const result = (await hookOf(sessionProvenancePlugin, 'before').handler(ctx)) as {
      context: Record<string, unknown>
    }
    Object.assign(ctx, result.context)
    ctx.context.session = { session: { token: 42 } }
    await afterHook().handler(ctx)
    expect(updateSession).not.toHaveBeenCalled()
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

  it('a 200 Response is a success too: it resets the budget and relabels', async () => {
    const { update, updateSession } = await run(
      '/two-factor/verify-totp',
      new Response('{}', { status: 200 }),
      stepUp('p')
    )
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({ update: { failedVerificationCount: 0, lockedUntil: null } })
    )
    expect(updateSession).toHaveBeenCalledWith('p', { authenticationMethod: 'two-factor' })
  })

  it.each([
    ['an expired OTP', APIError.from('BAD_REQUEST', { code: 'OTP_HAS_EXPIRED', message: 'x' })],
    ['an APIError without a body code', new APIError('UNAUTHORIZED')],
    ['a non-200 Response', new Response(null, { status: 401 })],
  ])('%s releases its reservation and resets nothing', async (_label, returned) => {
    const { incrementOne, update } = await run('/two-factor/verify-totp', returned, stepUp('p'))
    expect(incrementOne).toHaveBeenCalledTimes(2)
    expect(incrementOne).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ increment: { failedVerificationCount: 1 } })
    )
    expect(incrementOne).toHaveBeenLastCalledWith(
      expect.objectContaining({
        increment: { failedVerificationCount: -1 },
        where: expect.arrayContaining([
          expect.objectContaining({ field: 'failedVerificationCount', operator: 'gte', value: 1 }),
        ]) as unknown,
      })
    )
    expect(update).not.toHaveBeenCalled()
  })

  it('reserves BEFORE the endpoint runs and refuses a reservation beyond the budget', async () => {
    const overBudget = vi.fn<Op>(() => Promise.resolve({ failedVerificationCount: 11 }))
    const refused = run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        incrementOne: overBudget,
      }
    )
    await expect(refused).rejects.toMatchObject({
      statusCode: 429,
      body: { code: 'ACCOUNT_TEMPORARILY_LOCKED' },
    })
    // The reservation, then the lock (guarded on the spent budget).
    expect(overBudget).toHaveBeenCalledTimes(2)
    expect(overBudget).toHaveBeenLastCalledWith(
      expect.objectContaining({ set: { lockedUntil: expect.any(Date) as unknown } })
    )
  })

  it('fails closed when the reservation returns no counter', async () => {
    await expect(
      run(
        '/two-factor/verify-totp',
        { token: 'p' },
        {
          ...stepUp('p'),
          incrementOne: () => Promise.resolve({ failedVerificationCount: 'x' }),
        }
      )
    ).rejects.toThrow('the attempt could not be reserved')
    await expect(
      run(
        '/two-factor/verify-totp',
        { token: 'p' },
        {
          ...stepUp('p'),
          incrementOne: () => Promise.resolve(null),
        }
      )
    ).rejects.toThrow('the attempt could not be reserved')
  })

  it('reserves nothing when the row vanished meanwhile (Better Auth answers)', async () => {
    const findOne = vi.fn<Op>((query) =>
      Promise.resolve(
        JSON.stringify(query.where).includes('"userId"') ? { id: 'tf-1', verified: true } : null
      )
    )
    const { incrementOne, updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'p' },
      { ...stepUp('p'), findOne }
    )
    expect(incrementOne).not.toHaveBeenCalled()
    expect(updateSession).toHaveBeenCalled()
  })

  it('never counts row users on the sign-in path (Better Auth counts there itself)', async () => {
    const { incrementOne, create } = await run('/two-factor/verify-totp', wrongCode, {
      cookie: signed('challenge-id', SECRET, CHALLENGE_COOKIE),
    })
    expect(incrementOne).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
  })

  it('logs and swallows a failed settle write; a failed reservation refuses', async () => {
    const error = vi.fn()
    const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error, child: vi.fn() }
    const plugin = createSessionProvenancePlugin({ logger })
    // The reservation itself failing refuses the request (fail closed).
    await expect(
      run('/two-factor/verify-totp', wrongCode, {
        ...stepUp('p'),
        plugin,
        incrementOne: () => Promise.reject(new Error('db down')),
      })
    ).rejects.toThrow('db down')
    // A settle write failing is logged; the outcome stands.
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'p' },
      { ...stepUp('p'), plugin, update: () => Promise.reject(new Error('db down')) }
    )
    expect(updateSession).toHaveBeenCalled()
    await run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        plugin,
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- the case under test
        update: () => Promise.reject('opaque'),
      }
    )
    expect(error).toHaveBeenCalledWith(
      'better-auth two-factor step-up: failure counter write failed',
      expect.objectContaining({ userId: 'u-1', outcome: 'success', cause: 'db down' })
    )
    expect(error).toHaveBeenCalledWith(
      'better-auth two-factor step-up: failure counter write failed',
      expect.objectContaining({ cause: 'unknown' })
    )
  })
})

describe('failure budget without a twoFactor row (OTP-only, GHSA-xgx5-2cj5-x548)', () => {
  const wrongCode = APIError.from('UNAUTHORIZED', { code: 'INVALID_CODE', message: 'Invalid code' })
  const attempt = 'payload-auth-link:two-factor-attempt:u-1'

  it('a step-up inserts an attempt row before the endpoint; a wrong guess keeps it', async () => {
    const { create, count, remove, deleteMany } = await run('/two-factor/verify-otp', wrongCode, {
      ...stepUp('p'),
      row: null,
    })
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        model: 'verification',
        data: expect.objectContaining({ identifier: attempt }) as unknown,
      })
    )
    expect(count).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.arrayContaining([
          expect.objectContaining({ field: 'identifier', value: attempt }),
          expect.objectContaining({ field: 'expiresAt', operator: 'gt' }),
        ]) as unknown,
      })
    )
    expect(remove).not.toHaveBeenCalled()
    expect(deleteMany).not.toHaveBeenCalled()
  })

  it('a success clears the window; another failure releases its own row', async () => {
    const ok = await run('/two-factor/verify-otp', { token: 'p' }, { ...stepUp('p'), row: null })
    expect(ok.deleteMany).toHaveBeenCalledWith({
      model: 'verification',
      where: [{ field: 'identifier', value: attempt }],
    })
    const expired = APIError.from('BAD_REQUEST', { code: 'OTP_HAS_EXPIRED', message: 'x' })
    const failed = await run('/two-factor/verify-otp', expired, { ...stepUp('p'), row: null })
    expect(failed.remove).toHaveBeenCalledWith({
      model: 'verification',
      where: [{ field: 'id', value: 'v-1' }],
    })
  })

  it.each([
    ['the window is spent', 11],
    ['the count is unreadable', 'x'],
  ])('refuses (429) and removes its own row when %s', async (_label, liveAttempts) => {
    const outcome = run(
      '/two-factor/verify-otp',
      { token: 'p' },
      {
        ...stepUp('p'),
        row: null,
        liveAttempts,
      }
    )
    await expect(outcome).rejects.toMatchObject({ statusCode: 429 })
  })

  it('fails closed when the attempt row gets no id', async () => {
    await expect(
      run('/two-factor/verify-otp', { token: 'p' }, { ...stepUp('p'), row: null, created: {} })
    ).rejects.toThrow('the attempt could not be reserved')
  })

  it('counts the sign-in path too, for the user the challenge cookie names', async () => {
    const { create, deleteMany } = await run(
      '/two-factor/verify-otp',
      { token: 'fresh' },
      {
        cookie: signed('challenge-id', SECRET, CHALLENGE_COOKIE),
        setCookies: [`${COOKIE}=fresh.sig; Path=/`],
        row: null,
      }
    )
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ identifier: attempt }) as unknown })
    )
    expect(deleteMany).toHaveBeenCalled()
  })

  it.each([
    ['no challenge cookie', {}],
    ['an unsigned challenge cookie', { cookie: `${CHALLENGE_COOKIE}=challenge-id` }],
    [
      'a challenge naming no user',
      { cookie: signed('challenge-id', SECRET, CHALLENGE_COOKIE), challengeUser: '' },
    ],
    [
      'no secret to verify it with',
      { cookie: signed('challenge-id', SECRET, CHALLENGE_COOKIE), secret: '' },
    ],
  ] as const)('a sign-in with %s reserves nothing (Better Auth refuses it)', async (_l, extra) => {
    const { create } = await run('/two-factor/verify-otp', wrongCode, { row: null, ...extra })
    expect(create).not.toHaveBeenCalled()
  })

  it('a sign-in reserves nothing when the challenge cookie name cannot be resolved', async () => {
    const { create } = await run('/two-factor/verify-otp', wrongCode, {
      cookie: signed('challenge-id', SECRET, CHALLENGE_COOKIE),
      row: null,
      createAuthCookie: () => ({}),
    })
    expect(create).not.toHaveBeenCalled()
  })

  it('reserves nothing while Better Auth lockout is disabled', async () => {
    const { create } = await run('/two-factor/verify-otp', wrongCode, {
      ...stepUp('p'),
      row: null,
      twoFactorOptions: { accountLockout: { enabled: false } },
    })
    expect(create).not.toHaveBeenCalled()
  })
})

describe('a factor issued after the session was created proves nothing (GHSA-xgx5-2cj5-x548)', () => {
  const issued = 'payload-auth-link:two-factor-issued:u-1'
  const now = Date.now()
  const marker = (at: number | string) => ({
    id: `m-${String(at)}`,
    value: typeof at === 'number' ? new Date(at).toISOString() : at,
  })

  it.each([
    ['no marker (enrolled before this guard)', [], new Date(now), true],
    ['a marker older than the session', [marker(now - 60_000)], new Date(now), true],
    ['the newest of several markers older', [marker(now - 9e5), marker(now - 6e4)], now, true],
    ['a marker newer than the session', [marker(now)], new Date(now - 60_000), false],
    ['a marker in the same millisecond', [marker(now)], new Date(now), false],
    ['an unreadable marker', [marker('garbage')], new Date(now), false],
    ['a session without a creation time', [marker(now - 60_000)], undefined, false],
  ] as const)('with %s, a step-up relabels: %s', async (_label, markers, createdAt, relabels) => {
    const { updateSession } = await run(
      '/two-factor/verify-totp',
      { token: 'p' },
      {
        ...stepUp('p'),
        markers,
        createdAt,
      }
    )
    expect(updateSession).toHaveBeenCalledTimes(relabels ? 1 : 0)
  })

  it('an enrolment marks the factor issued before the endpoint AND after it succeeds', async () => {
    const { create, remove } = await run(
      '/two-factor/verify-totp',
      { token: 'old' },
      {
        ...stepUp('old'),
        twoFactorEnabled: false,
        row: { id: 'tf-1', verified: false },
        // A row without an id cannot be removed; readers take the max.
        markers: [marker(now - 60_000), { value: new Date(now - 9e5).toISOString() }],
      }
    )
    const markerWrites = create.mock.calls.filter(
      ([query]) => (query.data as { identifier?: unknown }).identifier === issued
    )
    expect(markerWrites).toHaveLength(2)
    // The superseded marker goes once the new one is written.
    expect(remove).toHaveBeenCalledWith({
      model: 'verification',
      where: [{ field: 'id', value: `m-${String(now - 60_000)}` }],
    })
  })

  it('a failed enrolment attempt marks before the endpoint only', async () => {
    const wrongCode = APIError.from('UNAUTHORIZED', { code: 'INVALID_CODE', message: 'x' })
    const { create } = await run('/two-factor/verify-totp', wrongCode, {
      ...stepUp('old'),
      twoFactorEnabled: false,
      row: { id: 'tf-1', verified: false },
    })
    expect(
      create.mock.calls.filter(
        ([query]) => (query.data as { identifier?: unknown }).identifier === issued
      )
    ).toHaveLength(1)
  })

  it('fails closed when the marker lookup returns no rows array', async () => {
    const plugin = createSessionProvenancePlugin()
    const before = hookOf(plugin, 'before')
    const ctx = {
      path: '/two-factor/verify-totp',
      headers: new Headers({ cookie: signed('p') }),
      context: {
        secret: SECRET,
        session: resolvedSession('p'),
        internalAdapter: {
          findSession: () =>
            Promise.resolve({
              session: { token: 'p', createdAt: new Date() },
              user: { id: 'u-1', twoFactorEnabled: true },
            }),
        },
        adapter: {
          findOne: () => Promise.resolve({ id: 'tf-1', verified: true }),
          findMany: () => Promise.resolve(null),
          incrementOne: () => Promise.resolve({ failedVerificationCount: 1 }),
        },
      },
    }
    await expect(before.handler(ctx)).rejects.toThrow('marker lookup returned no rows array')
    // An adapter missing an operation the guard needs is refused too.
    const bare = { ...ctx, context: { ...ctx.context, adapter: {} } }
    await expect(before.handler(bare)).rejects.toThrow('adapter.findMany is unavailable')
  })

  it('resolves the user by id when the session row carries none', async () => {
    const findUserById = vi.fn(() => Promise.resolve({ id: 'u-1', twoFactorEnabled: true }))
    const updateSession = vi.fn(() => Promise.resolve(null))
    const plugin = createSessionProvenancePlugin()
    const ctx: Record<string, unknown> = {
      path: '/two-factor/verify-totp',
      headers: new Headers({ cookie: signed('p') }),
      context: {
        returned: { token: 'p' },
        secret: SECRET,
        session: resolvedSession('p'),
        authCookies: { sessionToken: { name: COOKIE } },
        responseHeaders: new Headers(),
        internalAdapter: {
          updateSession,
          findSession: () => Promise.resolve({ session: { token: 'p', createdAt: new Date() } }),
          findUserById,
        },
        adapter: {
          findOne: () => Promise.resolve({ id: 'tf-1', verified: true }),
          findMany: () => Promise.resolve([]),
          incrementOne: () => Promise.resolve({ failedVerificationCount: 1 }),
          update: () => Promise.resolve(null),
        },
      },
    }
    const result = (await hookOf(plugin, 'before').handler(ctx)) as {
      context: Record<string, unknown>
    }
    Object.assign(ctx, result.context)
    await hookOf(plugin, 'after').handler(ctx)
    expect(findUserById).toHaveBeenCalledWith('u-1')
    expect(updateSession).toHaveBeenCalledWith('p', { authenticationMethod: 'two-factor' })
  })
})

describe('managing an enrolled factor requires an MFA session (GHSA-xgx5-2cj5-x548)', () => {
  const issued = 'payload-auth-link:two-factor-issued:u-1'
  const issuingPaths = [
    '/two-factor/enable',
    '/two-factor/get-totp-uri',
    '/two-factor/generate-backup-codes',
  ] as const

  function markerWrites(create: ReturnType<typeof vi.fn<Op>>): number {
    return create.mock.calls.filter(
      ([query]) => (query.data as { identifier?: unknown }).identifier === issued
    ).length
  }

  it('the management hooks match only the factor routes', () => {
    const before = sessionProvenancePlugin.hooks?.before?.[1]
    const after = sessionProvenancePlugin.hooks?.after?.[1]
    if (before === undefined || after === undefined) {
      throw new Error('management hooks missing')
    }
    for (const path of [...issuingPaths, '/two-factor/disable']) {
      expect(before.matcher({ path } as Parameters<typeof before.matcher>[0])).toBe(true)
    }
    expect(
      after.matcher({ path: '/two-factor/disable' } as Parameters<typeof after.matcher>[0])
    ).toBe(false)
    expect(
      before.matcher({ path: '/two-factor/verify-totp' } as Parameters<typeof before.matcher>[0])
    ).toBe(false)
    expect(before.matcher({} as Parameters<typeof before.matcher>[0])).toBe(false)
    expect(after.matcher({} as Parameters<typeof after.matcher>[0])).toBe(false)
  })

  it.each([...issuingPaths, '/two-factor/disable'])(
    '%s is refused (403) for an enrolled user on a single-factor session',
    async (path) => {
      for (const firstFactor of ['password', 'magic-link', null]) {
        await expect(
          run(path, { status: true }, { ...stepUp('p'), firstFactor })
        ).rejects.toMatchObject({ statusCode: 403, body: { code: 'TWO_FACTOR_SESSION_REQUIRED' } })
      }
    }
  )

  it.each(issuingPaths)(
    '%s from an MFA session proceeds and marks the factor issued',
    async (path) => {
      for (const firstFactor of ['two-factor', 'server-step-up']) {
        const { create } = await run(path, { status: true }, { ...stepUp('p'), firstFactor })
        // Before the endpoint, and again after it succeeded.
        expect(markerWrites(create)).toBe(2)
      }
    }
  )

  it('a failed issuing request marks before the endpoint only', async () => {
    const { create } = await run('/two-factor/get-totp-uri', new APIError('BAD_REQUEST'), {
      ...stepUp('p'),
      firstFactor: 'two-factor',
    })
    expect(markerWrites(create)).toBe(1)
  })

  it('disable from an MFA session proceeds without a marker', async () => {
    const { create } = await run(
      '/two-factor/disable',
      { status: true },
      {
        ...stepUp('p'),
        firstFactor: 'two-factor',
      }
    )
    expect(markerWrites(create)).toBe(0)
  })

  it.each([
    ['2FA off', { twoFactorEnabled: false }],
    ['an unconfirmed TOTP row only', { row: { id: 'tf-1', verified: false } }],
    ['OTP-only 2FA over the inbox', { row: null }],
  ] as const)('a user with %s may (re-)enrol from a password session', async (_label, extra) => {
    const { create } = await run(
      '/two-factor/enable',
      { method: 'totp' },
      {
        ...stepUp('p'),
        ...extra,
      }
    )
    expect(markerWrites(create)).toBe(2)
  })

  it('an OTP-only user is gated when the OTP channel is declared independent', async () => {
    const plugin = createSessionProvenancePlugin({ twoFactorOtpChannelIndependent: true })
    await expect(
      run('/two-factor/enable', { method: 'totp' }, { ...stepUp('p'), row: null, plugin })
    ).rejects.toMatchObject({ statusCode: 403 })
  })

  it('without a session it defers to Better Auth (which refuses with 401)', async () => {
    const { create } = await run('/two-factor/get-totp-uri', new APIError('UNAUTHORIZED'), {})
    expect(markerWrites(create)).toBe(0)
  })

  it('an issuing after-hook without this module’s assessment marks nothing', async () => {
    const after = sessionProvenancePlugin.hooks?.after?.[1] as unknown as Hook
    const create = vi.fn()
    await after.handler({
      path: '/two-factor/enable',
      context: { returned: { status: true }, adapter: { create } },
      payloadAuthLinkFactorManagement: { userId: 'u-1', holdsMfaFactor: false, method: null },
    })
    expect(create).not.toHaveBeenCalled()
  })
})
