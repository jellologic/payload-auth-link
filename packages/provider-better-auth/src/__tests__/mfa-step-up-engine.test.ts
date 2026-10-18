/**
 * GHSA-38wx-69j6-cgm7 and GHSA-xgx5-2cj5-x548 — MFA step-up on an
 * EXISTING session, on a real Better Auth 1.7 engine (twoFactor with
 * TOTP, backup codes and an emailed OTP; magicLink; emailOTP; password
 * reset) on real Payload storage (SQLite in memory) behind a real
 * `authLink` boot with `requireMfaForRoles: ['admin']`.
 *
 * Since #110 a correct second factor on an existing session relabels
 * it `two-factor`. Better Auth itself counts failed codes and locks
 * the account only on the sign-in challenge path (and only for users
 * with a `twoFactor` row), and its enrolment confirmation is itself a
 * "correct second factor on a session". Each test below fails without
 * the guard (step-up.ts, session-provenance.ts):
 *
 * - wrong step-up codes spend the shared failure budget, the account
 *   locks, and a correct code is refused (429) while it is locked —
 *   on the step-up AND the sign-in path, whichever spent the budget;
 *   a concurrent burst evaluates no more codes than the budget allows;
 *   OTP-only enrolments (no `twoFactor` row) have a budget too;
 * - enrolling a factor on a session (all a password-only attacker can
 *   do) never makes THAT session MFA-proven — not on the enrolment
 *   request, not on any later request; only a session created after
 *   the enrolment can step up with it;
 * - an enrolled factor can be read (`get-totp-uri`), re-issued
 *   (`generate-backup-codes`), re-enabled or disabled only from an
 *   MFA-proven session, and what such a call reveals steps up no
 *   session that already existed;
 * - an emailed two-factor OTP is not a second factor by default — on a
 *   step-up or on the sign-in challenge (the inbox can reset the
 *   password);
 * - second-factor responses carry no raw session token (issue #116).
 */
import { createHmac } from 'node:crypto'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { emailOTP, magicLink, twoFactor } from 'better-auth/plugins'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://mfa-step-up.test'
const SECRET = 'mfa-step-up-engine-secret!!!!!!!'
const PASSWORD = 'correct-horse-battery'
const RESET_PASSWORD = 'reset-by-the-inbox-holder'
/** Better Auth's default `accountLockout.maxFailedAttempts`. */
const MAX_FAILED = 10
/** Better Auth's default per-OTP attempt cap (`otpOptions.allowedAttempts`). */
const OTP_ATTEMPTS = 5

const sentTwoFactorOtps: { email: string; otp: string }[] = []
const sentMagicLinks: { email: string; url: string }[] = []
const sentEmailOtps: { email: string; otp: string }[] = []
const sentResets: { email: string; token: string }[] = []

let config: SanitizedConfig
let payload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!payload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(payload)
  },
  autoDeclare: true,
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    // BA's per-route limits would 429 the deliberate wrong-code bursts
    // before the account lockout under test does.
    rateLimit: { enabled: false },
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: false,
      sendResetPassword: ({ user, token }) => {
        sentResets.push({ email: user.email, token })
        return Promise.resolve()
      },
    },
    plugins: [
      twoFactor({
        otpOptions: {
          sendOTP: ({ user, otp }) => {
            sentTwoFactorOtps.push({ email: user.email, otp })
            return Promise.resolve()
          },
        },
      }),
      magicLink({
        sendMagicLink: ({ email, url }) => {
          sentMagicLinks.push({ email, url })
          return Promise.resolve()
        },
      }),
      emailOTP({
        sendVerificationOTP: ({ email, otp }) => {
          sentEmailOtps.push({ email, otp })
          return Promise.resolve()
        },
      }),
    ],
  },
})

function live(): Payload {
  if (!payload) {
    throw new Error('Payload not ready')
  }
  return payload
}

/** Decode an RFC 4648 base32 string (the `secret` of an otpauth:// URI). */
function base32Decode(encoded: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let buffer = 0
  let bits = 0
  const bytes: number[] = []
  for (const char of encoded.replace(/=+$/, '').toUpperCase()) {
    const value = alphabet.indexOf(char)
    if (value === -1) {
      throw new Error(`not a base32 character: ${char}`)
    }
    buffer = ((buffer << 5) | value) & 0xffff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >> bits) & 0xff)
    }
  }
  return Buffer.from(bytes)
}

/** RFC 4226 HOTP (HMAC-SHA1, 6 digits). */
function hotp(key: Buffer, counter: number): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', key).update(message).digest()
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f
  const binary = digest.readUInt32BE(offset) & 0x7fffffff
  return String(binary % 1_000_000).padStart(6, '0')
}

/** The current RFC 6238 TOTP code (30s step). */
function totpNow(secret: string): string {
  return hotp(base32Decode(secret), Math.floor(Date.now() / 30_000))
}

/** A code wrong for every step BA could accept around now. */
function wrongTotp(secret: string): string {
  const step = Math.floor(Date.now() / 30_000)
  const key = base32Decode(secret)
  const accepted = new Set([step - 2, step - 1, step, step + 1, step + 2].map((c) => hotp(key, c)))
  let code = '000000'
  while (accepted.has(code)) {
    code = String((Number(code) + 1) % 1_000_000).padStart(6, '0')
  }
  return code
}

/** A six-digit code that is not `otp`. */
function wrongOtp(otp: string): string {
  return otp === '000000' ? '111111' : '000000'
}

function authRequest(
  path: string,
  init: { method?: string; body?: unknown; cookie?: string } = {}
): Request {
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: init.method ?? 'GET',
    headers: {
      origin: ORIGIN,
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(init.cookie === undefined ? {} : { cookie: init.cookie }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  })
}

function post(path: string, body: unknown, cookie?: string): Promise<Response> {
  return engine.auth.handler(
    authRequest(path, { method: 'POST', body, ...(cookie === undefined ? {} : { cookie }) })
  )
}

/** The session cookie pair a response set, or `null`. */
function sessionCookieOrNull(response: Response): string | null {
  const name = engine.sessionCookieNames[0] ?? ''
  const entry = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
  const pair = entry?.split(';')[0]
  return pair === undefined || pair === `${name}=` ? null : pair
}

function sessionCookieOf(response: Response): string {
  const cookie = sessionCookieOrNull(response)
  if (cookie === null) {
    throw new Error(`no session cookie set (status ${String(response.status)})`)
  }
  return cookie
}

/** The raw session token inside a signed session cookie pair. */
function rawTokenOf(cookie: string): string {
  const value = decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1))
  return value.slice(0, value.lastIndexOf('.'))
}

/** Every cookie pair a response set (the 2FA challenge cookie included). */
function cookieJarOf(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((entry) => entry.split(';')[0] ?? '')
    .filter((pair) => pair !== '' && !pair.endsWith('='))
    .join('; ')
}

let counter = 0
function uniqueEmail(prefix: string): string {
  counter += 1
  return `${prefix}-${String(counter)}@mfa-step-up.test`
}

async function signUp(email: string): Promise<string> {
  const response = await post('/sign-up/email', { name: 'Step Up', email, password: PASSWORD })
  expect(response.status).toBe(200)
  const body = (await response.json()) as { user?: { id?: unknown } }
  if (typeof body.user?.id !== 'string') {
    throw new Error('sign-up returned no user id')
  }
  await live().update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: true },
    overrideAccess: true,
  })
  return body.user.id
}

async function passwordSession(email: string): Promise<string> {
  const response = await post('/sign-in/email', { email, password: PASSWORD })
  expect(response.status).toBe(200)
  return sessionCookieOf(response)
}

async function assuranceOf(
  cookie: string
): Promise<{ readonly methods: readonly string[] | 'unknown'; readonly mfa: unknown }> {
  const session = await engine.provider.getSession(new Headers({ cookie }))
  if (session.isErr() || session.value === null) {
    throw new Error(session.isErr() ? session.error.message : 'no session')
  }
  return session.value.assurance
}

/** The plugin's session endpoint: the roles a session actually holds. */
async function pluginRoles(
  cookie: string
): Promise<{ roles: readonly string[] | undefined; mfaRequired: unknown }> {
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
  })
  expect(response.status).toBe(200)
  const body = (await response.json()) as {
    user: { roles?: string[]; mfaRequired?: boolean } | null
  }
  return { roles: body.user?.roles, mfaRequired: body.user?.mfaRequired }
}

async function grantAdmin(email: string, cookie: string): Promise<void> {
  // Provision the Payload user through the plugin, then grant the role.
  await pluginRoles(cookie)
  await live().update({
    collection: 'users',
    where: { email: { equals: email } },
    data: { roles: ['admin', 'user'] },
    overrideAccess: true,
  })
}

/** Start TOTP enrolment on a session; returns the TOTP secret and backup codes. */
async function enable(cookie: string): Promise<{ secret: string; backupCodes: string[] }> {
  const enabled = await post('/two-factor/enable', { password: PASSWORD }, cookie)
  expect(enabled.status).toBe(200)
  const body = (await enabled.json()) as { totpURI?: unknown; backupCodes?: unknown }
  if (typeof body.totpURI !== 'string' || !Array.isArray(body.backupCodes)) {
    throw new Error('two-factor enable returned no totpURI / backup codes')
  }
  const secret = new URL(body.totpURI).searchParams.get('secret')
  if (secret === null) {
    throw new Error('totpURI carries no secret')
  }
  return { secret, backupCodes: body.backupCodes.filter((c): c is string => typeof c === 'string') }
}

function verifyTotp(code: string, cookie: string): Promise<Response> {
  return post('/two-factor/verify-totp', { code }, cookie)
}

/**
 * An enrolled user and an existing PASSWORD session: enrolment
 * confirms on its own session (which BA rotates; the rotated session
 * keeps its `password` label).
 */
async function enrolledUser(prefix: string): Promise<{
  email: string
  userId: string
  secret: string
  backupCodes: string[]
  cookie: string
}> {
  const email = uniqueEmail(prefix)
  const userId = await signUp(email)
  const first = await passwordSession(email)
  const { secret, backupCodes } = await enable(first)
  const confirmed = await verifyTotp(totpNow(secret), first)
  expect(confirmed.status, `enroll: ${await confirmed.clone().text()}`).toBe(200)
  return { email, userId, secret, backupCodes, cookie: sessionCookieOf(confirmed) }
}

/** A fresh magic-link session (Better Auth runs no 2FA challenge on this path). */
async function magicLinkSession(email: string): Promise<string> {
  const requested = await post('/sign-in/magic-link', { email, callbackURL: '/account' })
  expect(requested.status).toBe(200)
  const link = sentMagicLinks.findLast((entry) => entry.email === email)
  if (link === undefined) {
    throw new Error('magic link was not captured')
  }
  // Without a callbackURL BA answers the verification with a 200 body
  // (the redirect variant records no method at all, which proves
  // nothing either way).
  const url = new URL(link.url)
  url.searchParams.delete('callbackURL')
  const followed = await engine.auth.handler(
    authRequest(`${url.pathname.replace(/^\/api\/auth/, '')}${url.search}`)
  )
  const cookie = sessionCookieOf(followed)
  expect((await assuranceOf(cookie)).methods).toEqual(['magic-link'])
  return cookie
}

/** Start a password sign-in for an enrolled user: the 2FA challenge cookie jar. */
async function challenge(email: string, password = PASSWORD, cookie?: string): Promise<string> {
  const started = await post('/sign-in/email', { email, password }, cookie)
  expect(started.status).toBe(200)
  expect(((await started.json()) as { twoFactorRedirect?: unknown }).twoFactorRedirect).toBe(true)
  return cookieJarOf(started)
}

/** Password + TOTP sign-in; returns the session cookie and every cookie it set. */
async function mfaSignIn(
  email: string,
  secret: string,
  trustDevice = false
): Promise<{ cookie: string; jar: string }> {
  const jar = await challenge(email)
  const verified = await post(
    '/two-factor/verify-totp',
    { code: totpNow(secret), trustDevice },
    jar
  )
  expect(verified.status).toBe(200)
  return { cookie: sessionCookieOf(verified), jar: cookieJarOf(verified) }
}

/**
 * A PASSWORD session created after enrolment: a trusted device skips
 * Better Auth's challenge, so the session is labelled `password`.
 */
async function trustedPasswordSession(email: string, secret: string): Promise<string> {
  const { jar } = await mfaSignIn(email, secret, true)
  const trust = jar.split('; ').find((pair) => pair.includes('trust_device='))
  if (trust === undefined) {
    throw new Error('no trust-device cookie set')
  }
  const response = await post('/sign-in/email', { email, password: PASSWORD }, trust)
  expect(response.status).toBe(200)
  const cookie = sessionCookieOf(response)
  expect((await assuranceOf(cookie)).methods).toEqual(['password'])
  return cookie
}

type CounterRow = {
  failedVerificationCount?: unknown
  lockedUntil?: unknown
  id?: unknown
  secret?: unknown
  backupCodes?: unknown
}

async function counterOrNull(userId: string): Promise<CounterRow | null> {
  const ctx = await engine.auth.$context
  return ctx.adapter.findOne<CounterRow>({
    model: 'twoFactor',
    where: [{ field: 'userId', value: userId }],
  })
}

async function counterOf(userId: string): Promise<CounterRow> {
  const row = await counterOrNull(userId)
  if (row === null) {
    throw new Error('no twoFactor row')
  }
  return row
}

async function setLockedUntil(userId: string, lockedUntil: Date): Promise<void> {
  const ctx = await engine.auth.$context
  await ctx.adapter.update({
    model: 'twoFactor',
    where: [{ field: 'userId', value: userId }],
    update: { lockedUntil },
  })
}

async function spendWrongStepUps(secret: string, cookie: string, count: number): Promise<void> {
  for (let attempt = 0; attempt < count; attempt += 1) {
    const wrong = await verifyTotp(wrongTotp(secret), cookie)
    expect(wrong.status, `wrong code #${String(attempt + 1)}`).toBe(401)
  }
}

/** Send a two-factor OTP (step-up session or sign-in challenge jar); returns it. */
async function sendTwoFactorOtp(email: string, cookie: string): Promise<string> {
  const sent = await post('/two-factor/send-otp', {}, cookie)
  expect(sent.status).toBe(200)
  const otp = sentTwoFactorOtps.findLast((entry) => entry.email === email)?.otp
  if (otp === undefined) {
    throw new Error('two-factor OTP was not captured')
  }
  return otp
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [engine.provider],
        policies: { requireMfaForRoles: ['admin'] },
      }),
    ],
  })
  payload = await getPayload({ config })
  await engine.auth.$context
}, 120_000)

describe('step-up lockout shares the sign-in failure budget', () => {
  it('wrong step-up codes lock the account; the correct code is refused while locked', async () => {
    const { userId, secret, cookie } = await enrolledUser('lockout')
    await spendWrongStepUps(secret, cookie, MAX_FAILED)
    const row = await counterOf(userId)
    expect(row.failedVerificationCount).toBe(MAX_FAILED)
    expect(row.lockedUntil).toBeInstanceOf(Date)

    // The CORRECT code, while locked: refused before any check, and the
    // session is not relabelled.
    const locked = await verifyTotp(totpNow(secret), cookie)
    expect(locked.status).toBe(429)
    expect(((await locked.json()) as { code?: unknown }).code).toBe('ACCOUNT_TEMPORARILY_LOCKED')
    const after = await assuranceOf(cookie)
    expect(after.methods).toEqual(['password'])
    expect(after.mfa).toBe(false)
  })

  it('the step-up lock also locks the sign-in challenge (one shared budget)', async () => {
    const { email, secret, cookie } = await enrolledUser('lockout-shared')
    await spendWrongStepUps(secret, cookie, MAX_FAILED)
    const signIn = await verifyTotp(totpNow(secret), await challenge(email))
    expect(signIn.status).toBe(429)
    expect(sessionCookieOrNull(signIn)).toBeNull()
  })

  it('a lock spent on the sign-in path refuses a correct step-up', async () => {
    const { email, secret, cookie } = await enrolledUser('lockout-signin')
    // BA burns a sign-in challenge after 5 attempts: spend the budget
    // across two challenges.
    for (let challengeIndex = 0; challengeIndex < MAX_FAILED / 5; challengeIndex += 1) {
      const jar = await challenge(email)
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const wrong = await verifyTotp(wrongTotp(secret), jar)
        expect(wrong.status).toBe(401)
      }
    }
    const stepUp = await verifyTotp(totpNow(secret), cookie)
    expect(stepUp.status).toBe(429)
    expect((await assuranceOf(cookie)).methods).toEqual(['password'])
  })

  it('an expired lock is cleared and a correct step-up then succeeds', async () => {
    const { email, userId, secret } = await enrolledUser('lockout-expired')
    const session = await magicLinkSession(email)
    await spendWrongStepUps(secret, session, MAX_FAILED)
    await setLockedUntil(userId, new Date(Date.now() - 1000))
    const verified = await verifyTotp(totpNow(secret), session)
    expect(verified.status).toBe(200)
    expect((await assuranceOf(session)).methods).toEqual(['two-factor'])
    const row = await counterOf(userId)
    expect(row.failedVerificationCount).toBe(0)
    expect(row.lockedUntil ?? null).toBeNull()
  })

  it('a correct step-up resets the budget (it counts consecutive failures only)', async () => {
    const { userId, secret, cookie } = await enrolledUser('lockout-reset')
    await spendWrongStepUps(secret, cookie, MAX_FAILED - 1)
    expect((await counterOf(userId)).failedVerificationCount).toBe(MAX_FAILED - 1)
    const verified = await verifyTotp(totpNow(secret), cookie)
    expect(verified.status).toBe(200)
    expect((await counterOf(userId)).failedVerificationCount).toBe(0)
    await spendWrongStepUps(secret, cookie, 1)
    expect((await counterOf(userId)).lockedUntil ?? null).toBeNull()
  })

  it('a step-up that is not a guess (expired OTP) releases its reservation', async () => {
    const { userId, cookie } = await enrolledUser('lockout-release')
    // No OTP was sent: BA answers OTP_HAS_EXPIRED, which spends nothing.
    const expired = await post('/two-factor/verify-otp', { code: '123456' }, cookie)
    expect(expired.status).toBe(400)
    expect((await counterOf(userId)).failedVerificationCount).toBe(0)
  })
})

describe('concurrent attempts cannot outrun the budget (GHSA-xgx5-2cj5-x548)', () => {
  it('a burst of 40 wrong codes evaluates exactly the budget; the rest are refused', async () => {
    const { userId, secret, cookie } = await enrolledUser('burst')
    const statuses = await Promise.all(
      Array.from({ length: 40 }, async () => (await verifyTotp(wrongTotp(secret), cookie)).status)
    )
    expect(statuses.filter((status) => status === 401)).toHaveLength(MAX_FAILED)
    expect(statuses.filter((status) => status === 429)).toHaveLength(40 - MAX_FAILED)
    expect((await counterOf(userId)).lockedUntil).toBeInstanceOf(Date)
    expect((await verifyTotp(totpNow(secret), cookie)).status).toBe(429)
  })

  it('a burst of 40 wrong backup codes evaluates exactly the budget; the rest are refused', async () => {
    const { userId, backupCodes, cookie } = await enrolledUser('burst-backup')
    const wrong = 'not-a-real-backup-code'
    const statuses = await Promise.all(
      Array.from(
        { length: 40 },
        async () => (await post('/two-factor/verify-backup-code', { code: wrong }, cookie)).status
      )
    )
    // Backup codes carry no per-code cap of their own on a step-up, so
    // the reservation is what keeps the evaluation to the budget.
    expect(statuses.filter((status) => status === 401)).toHaveLength(MAX_FAILED)
    expect(statuses.filter((status) => status === 429)).toHaveLength(40 - MAX_FAILED)
    expect((await counterOf(userId)).lockedUntil).toBeInstanceOf(Date)
    // A REAL code is refused while the lock holds, and stays spendable.
    const real = backupCodes[0]
    if (real === undefined) {
      throw new Error('no backup code issued')
    }
    expect((await post('/two-factor/verify-backup-code', { code: real }, cookie)).status).toBe(429)
  })

  it('a burst on the sign-in challenge mints no session and cannot exhaust the budget', async () => {
    const { email, userId, secret } = await enrolledUser('burst-signin')
    const jar = await challenge(email)
    const statuses = await Promise.all(
      Array.from({ length: 40 }, async () => (await verifyTotp(wrongTotp(secret), jar)).status)
    )
    // Row users on this path are Better Auth's to count (the plugin
    // reserves only for OTP-only users here). Its per-challenge counter
    // and its cap refuse every wrong code of a burst without ever
    // minting a session — 401, or 400 once the cap is reached.
    for (const status of statuses) {
      expect([400, 401]).toContain(status)
    }
    // The burst spent at most the per-challenge cap of the SHARED row
    // budget, so the account is not locked: a fresh challenge with the
    // correct code still signs in.
    expect((await counterOf(userId)).lockedUntil ?? null).toBeNull()
    const fresh = await mfaSignIn(email, secret)
    expect(await assuranceOf(fresh.cookie)).toEqual({ methods: ['two-factor'], mfa: true })
  })

  it('with 9 spent, a burst of wrong codes plus the right one cannot pass the budget', async () => {
    const { email, userId, secret } = await enrolledUser('burst-right')
    const session = await magicLinkSession(email)
    await spendWrongStepUps(secret, session, MAX_FAILED - 1)
    const attempts = [
      ...Array.from({ length: 5 }, () => ({ code: wrongTotp(secret), right: false })),
      { code: totpNow(secret), right: true },
    ]
    const burst = await Promise.all(
      attempts.map(async ({ code, right }) => ({
        right,
        status: (await verifyTotp(code, session)).status,
      }))
    )
    // One slot was left: at most one wrong code was evaluated, and
    // the right code succeeded only if IT took that slot.
    expect(burst.filter((entry) => !entry.right && entry.status === 401).length).toBeLessThan(2)
    const rightWon = burst.some((entry) => entry.right && entry.status === 200)
    expect((await assuranceOf(session)).mfa).toBe(rightWon)
    expect((await counterOf(userId)).lockedUntil instanceof Date).toBe(!rightWon)
  })
})

describe('enrolling a factor is never MFA proof for that session', () => {
  it('a password-only attacker enrolling their own TOTP does not unlock the MFA-gated role', async () => {
    const email = uniqueEmail('attacker-totp')
    await signUp(email)
    // The victim holds an MFA-gated role and never enrolled 2FA.
    const attacker = await passwordSession(email)
    await grantAdmin(email, attacker)
    expect(await pluginRoles(attacker)).toEqual({ roles: ['user'], mfaRequired: true })

    // The attacker knows only the password: enable, then confirm with
    // THEIR authenticator.
    const { secret, backupCodes } = await enable(attacker)
    const confirmed = await verifyTotp(totpNow(secret), attacker)
    expect(confirmed.status).toBe(200)
    // BA rotates the session; the rotated one keeps the password label.
    const rotated = sessionCookieOf(confirmed)
    expect(await assuranceOf(rotated)).toEqual({ methods: ['password'], mfa: false })
    expect(await pluginRoles(rotated)).toEqual({ roles: ['user'], mfaRequired: true })

    // GHSA-xgx5-2cj5-x548: the SECOND verification on the same session
    // (now with an enrolled factor) proves nothing either.
    const again = await verifyTotp(totpNow(secret), rotated)
    expect(again.status).toBe(200)
    const code = backupCodes[0]
    if (code === undefined) {
      throw new Error('no backup code issued')
    }
    const backup = await post('/two-factor/verify-backup-code', { code }, rotated)
    expect(backup.status).toBe(200)
    expect(await assuranceOf(rotated)).toEqual({ methods: ['password'], mfa: false })
    expect(await pluginRoles(rotated)).toEqual({ roles: ['user'], mfaRequired: true })
  })

  it('a session that already existed at enrolment cannot be stepped up with the factor', async () => {
    const email = uniqueEmail('attacker-parallel')
    await signUp(email)
    const parallel = await passwordSession(email)
    const enrolling = await passwordSession(email)
    const { secret } = await enable(enrolling)
    expect((await verifyTotp(totpNow(secret), enrolling)).status).toBe(200)
    const stepUp = await verifyTotp(totpNow(secret), parallel)
    expect(stepUp.status).toBe(200)
    expect(await assuranceOf(parallel)).toEqual({ methods: ['password'], mfa: false })
  })

  it('a backup code of an unconfirmed enrolment proves nothing', async () => {
    const email = uniqueEmail('attacker-backup')
    await signUp(email)
    const attacker = await passwordSession(email)
    const { backupCodes } = await enable(attacker)
    const code = backupCodes[0]
    if (code === undefined) {
      throw new Error('no backup code issued')
    }
    const used = await post('/two-factor/verify-backup-code', { code }, attacker)
    expect(used.status).toBe(200)
    expect(await assuranceOf(attacker)).toEqual({ methods: ['password'], mfa: false })
  })

  it('a session created AFTER the enrolment steps up with the enrolled factor', async () => {
    const { email, secret } = await enrolledUser('enrolled-stepup')
    const session = await magicLinkSession(email)
    await grantAdmin(email, session)
    expect(await pluginRoles(session)).toEqual({ roles: ['user'], mfaRequired: true })
    const verified = await verifyTotp(totpNow(secret), session)
    expect(verified.status).toBe(200)
    expect(await assuranceOf(session)).toEqual({ methods: ['two-factor'], mfa: true })
    expect((await pluginRoles(session)).roles).toEqual(['admin', 'user'])
  })
})

describe('an enrolled factor is managed only from an MFA-proven session', () => {
  async function rowSnapshot(userId: string): Promise<{ secret: unknown; backupCodes: unknown }> {
    const row = await counterOf(userId)
    return { secret: row.secret, backupCodes: row.backupCodes }
  }

  it.each([
    '/two-factor/get-totp-uri',
    '/two-factor/generate-backup-codes',
    '/two-factor/enable',
    '/two-factor/disable',
  ])('%s is refused (403) on a password session and changes nothing', async (path) => {
    const { userId, cookie } = await enrolledUser('manage-password')
    const before = await rowSnapshot(userId)
    const response = await post(path, { password: PASSWORD }, cookie)
    expect(response.status).toBe(403)
    const text = await response.text()
    expect((JSON.parse(text) as { code?: unknown }).code).toBe('TWO_FACTOR_SESSION_REQUIRED')
    expect(text).not.toContain('otpauth://')
    expect(text).not.toContain('backupCodes')
    expect(await rowSnapshot(userId)).toEqual(before)
  })

  it('refuses the secret-revealing routes on an inbox (magic-link) session too', async () => {
    const { email, userId } = await enrolledUser('manage-magic')
    const magic = await magicLinkSession(email)
    const before = await rowSnapshot(userId)
    for (const path of ['/two-factor/get-totp-uri', '/two-factor/generate-backup-codes']) {
      const response = await post(path, { password: PASSWORD }, magic)
      expect(response.status).toBe(403)
    }
    expect(await rowSnapshot(userId)).toEqual(before)
  })

  it('an MFA session may manage it; what it reveals steps up no session that existed', async () => {
    const { email, secret } = await enrolledUser('manage-mfa')
    const older = await magicLinkSession(email)
    const { cookie: mfa } = await mfaSignIn(email, secret)
    expect(await assuranceOf(mfa)).toEqual({ methods: ['two-factor'], mfa: true })

    const uri = await post('/two-factor/get-totp-uri', { password: PASSWORD }, mfa)
    expect(uri.status).toBe(200)
    expect(((await uri.json()) as { totpURI?: unknown }).totpURI).toEqual(
      expect.stringContaining(`secret=${secret}`)
    )
    const generated = await post('/two-factor/generate-backup-codes', { password: PASSWORD }, mfa)
    expect(generated.status).toBe(200)
    const fresh = ((await generated.json()) as { backupCodes?: string[] }).backupCodes?.[0]
    if (fresh === undefined) {
      throw new Error('no backup code generated')
    }

    // The freshly issued code (and the TOTP) on a session that predates
    // the issue: Better Auth accepts them, but they prove nothing here.
    expect((await post('/two-factor/verify-backup-code', { code: fresh }, older)).status).toBe(200)
    expect((await verifyTotp(totpNow(secret), older)).status).toBe(200)
    expect(await assuranceOf(older)).toEqual({ methods: ['magic-link'], mfa: false })

    // A session created after the issue steps up as usual.
    const newer = await magicLinkSession(email)
    expect((await verifyTotp(totpNow(secret), newer)).status).toBe(200)
    expect(await assuranceOf(newer)).toEqual({ methods: ['two-factor'], mfa: true })
  })

  it('a user without an enrolled factor still enrols from a password session', async () => {
    const email = uniqueEmail('manage-first')
    await signUp(email)
    const { secret } = await enable(await passwordSession(email))
    expect(secret).not.toBe('')
  })
})

describe('an emailed two-factor OTP is not a second factor by default', () => {
  async function stepUpWithEmailedOtp(email: string, cookie: string): Promise<Response> {
    const otp = await sendTwoFactorOtp(email, cookie)
    const verified = await post('/two-factor/verify-otp', { code: otp }, cookie)
    expect(verified.status, `verify-otp: ${await verified.clone().text()}`).toBe(200)
    return verified
  }

  it('does not make a magic-link session MFA-proven; TOTP still does', async () => {
    const { email, secret } = await enrolledUser('inbox-magic')
    const magic = await magicLinkSession(email)
    await stepUpWithEmailedOtp(email, magic)
    expect(await assuranceOf(magic)).toEqual({ methods: ['magic-link'], mfa: false })

    // An authenticator is independent of the inbox.
    const totp = await verifyTotp(totpNow(secret), magic)
    expect(totp.status).toBe(200)
    expect(await assuranceOf(magic)).toEqual({ methods: ['two-factor'], mfa: true })
  })

  it('does not make an email-OTP sign-in MFA-proven', async () => {
    const { email } = await enrolledUser('inbox-email-otp')
    const requested = await post('/email-otp/send-verification-otp', { email, type: 'sign-in' })
    expect(requested.status).toBe(200)
    const otp = sentEmailOtps.findLast((entry) => entry.email === email)?.otp
    if (otp === undefined) {
      throw new Error('email OTP was not captured')
    }
    const signedIn = await post('/sign-in/email-otp', { email, otp })
    expect(signedIn.status).toBe(200)
    const inbox = sessionCookieOf(signedIn)
    expect((await assuranceOf(inbox)).methods).toEqual(['email-otp'])

    await stepUpWithEmailedOtp(email, inbox)
    expect(await assuranceOf(inbox)).toEqual({ methods: ['email-otp'], mfa: false })
  })

  it('does not relabel a password session either (the inbox can reset the password)', async () => {
    const { email, secret } = await enrolledUser('inbox-password')
    const password = await trustedPasswordSession(email, secret)
    await stepUpWithEmailedOtp(email, password)
    expect(await assuranceOf(password)).toEqual({ methods: ['password'], mfa: false })
    expect((await verifyTotp(totpNow(secret), password)).status).toBe(200)
    expect(await assuranceOf(password)).toEqual({ methods: ['two-factor'], mfa: true })
  })

  it('a sign-in completed with an emailed OTP is not MFA (reset password → OTP)', async () => {
    const { email } = await enrolledUser('inbox-signin')
    // Whoever holds the inbox resets the password…
    const requested = await post('/request-password-reset', { email })
    expect(requested.status).toBe(200)
    const token = sentResets.findLast((entry) => entry.email === email)?.token
    if (token === undefined) {
      throw new Error('reset token was not captured')
    }
    const reset = await post('/reset-password', { newPassword: RESET_PASSWORD, token })
    expect(reset.status).toBe(200)
    // …signs in with it and completes the challenge from the same inbox.
    const jar = await challenge(email, RESET_PASSWORD)
    const otp = await sendTwoFactorOtp(email, jar)
    const verified = await post('/two-factor/verify-otp', { code: otp }, jar)
    expect(verified.status).toBe(200)
    const session = sessionCookieOf(verified)
    expect(await assuranceOf(session)).toEqual({ methods: ['password'], mfa: false })
    await grantAdmin(email, session)
    expect(await pluginRoles(session)).toEqual({ roles: ['user'], mfaRequired: true })
  })
})

describe('OTP-only enrolments have a failure budget too (GHSA-xgx5-2cj5-x548)', () => {
  /** Turn on OTP-only two-factor (no `twoFactor` row); returns the rotated session. */
  async function otpOnlyUser(
    prefix: string
  ): Promise<{ email: string; userId: string; cookie: string }> {
    const email = uniqueEmail(prefix)
    const userId = await signUp(email)
    const enabled = await post(
      '/two-factor/enable',
      { password: PASSWORD, method: 'otp' },
      await passwordSession(email)
    )
    expect(enabled.status).toBe(200)
    expect(await counterOrNull(userId)).toBeNull()
    return { email, userId, cookie: sessionCookieOf(enabled) }
  }

  /** Spend the budget in rounds of fresh OTPs (BA caps attempts per OTP). */
  async function spendWrongOtps(email: string, cookie: string): Promise<void> {
    for (let round = 0; round < MAX_FAILED / OTP_ATTEMPTS; round += 1) {
      const otp = await sendTwoFactorOtp(email, cookie)
      for (let attempt = 0; attempt < OTP_ATTEMPTS; attempt += 1) {
        const wrong = await post('/two-factor/verify-otp', { code: wrongOtp(otp) }, cookie)
        expect(wrong.status, `wrong OTP #${String(round * OTP_ATTEMPTS + attempt + 1)}`).toBe(401)
      }
    }
  }

  it('wrong step-up OTPs lock the account; the correct OTP is then refused', async () => {
    const { email, cookie } = await otpOnlyUser('otp-only-stepup')
    await spendWrongOtps(email, cookie)
    const otp = await sendTwoFactorOtp(email, cookie)
    const refused = await post('/two-factor/verify-otp', { code: otp }, cookie)
    expect(refused.status).toBe(429)
    expect(((await refused.json()) as { code?: unknown }).code).toBe('ACCOUNT_TEMPORARILY_LOCKED')
  })

  it('wrong sign-in OTPs lock the account; the correct OTP then mints no session', async () => {
    const { email } = await otpOnlyUser('otp-only-signin')
    const jar = await challenge(email)
    await spendWrongOtps(email, jar)
    const otp = await sendTwoFactorOtp(email, jar)
    const refused = await post('/two-factor/verify-otp', { code: otp }, jar)
    expect(refused.status).toBe(429)
    expect(sessionCookieOrNull(refused)).toBeNull()
  })

  it('a correct OTP resets the budget', async () => {
    const { email, cookie } = await otpOnlyUser('otp-only-reset')
    const first = await sendTwoFactorOtp(email, cookie)
    for (let attempt = 0; attempt < OTP_ATTEMPTS - 1; attempt += 1) {
      expect((await post('/two-factor/verify-otp', { code: wrongOtp(first) }, cookie)).status).toBe(
        401
      )
    }
    expect((await post('/two-factor/verify-otp', { code: first }, cookie)).status).toBe(200)
    // The full budget is available again.
    await spendWrongOtps(email, cookie)
    const otp = await sendTwoFactorOtp(email, cookie)
    expect((await post('/two-factor/verify-otp', { code: otp }, cookie)).status).toBe(429)
  })

  it('a concurrent burst of wrong OTPs cannot outrun the attempt-row budget', async () => {
    const { email, cookie } = await otpOnlyUser('otp-only-burst')
    const otp = await sendTwoFactorOtp(email, cookie)
    const statuses = await Promise.all(
      Array.from(
        { length: 40 },
        async () => (await post('/two-factor/verify-otp', { code: wrongOtp(otp) }, cookie)).status
      )
    )
    for (const status of statuses) {
      expect([400, 401, 429]).toContain(status)
    }
    // No more attempts reached the verification than the budget allows
    // (Better Auth's per-OTP cap bounds that lower); everything beyond
    // it was refused by the reservation, not evaluated.
    expect(statuses.filter((status) => status !== 429).length).toBeLessThanOrEqual(MAX_FAILED)
    expect(statuses.filter((status) => status === 429).length).toBeGreaterThanOrEqual(
      40 - MAX_FAILED
    )
  })
})

describe('second-factor responses carry no raw session token (issue #116)', () => {
  it('verify-totp, verify-otp and verify-backup-code {disableSession} omit it', async () => {
    const { email, secret, backupCodes } = await enrolledUser('redact')
    const session = await magicLinkSession(email)
    const raw = rawTokenOf(session)
    const bodies: string[] = []

    const totp = await verifyTotp(totpNow(secret), session)
    expect(totp.status).toBe(200)
    bodies.push(await totp.text())

    const otp = await sendTwoFactorOtp(email, session)
    const verifiedOtp = await post('/two-factor/verify-otp', { code: otp }, session)
    expect(verifiedOtp.status).toBe(200)
    bodies.push(await verifiedOtp.text())

    const code = backupCodes[1]
    if (code === undefined) {
      throw new Error('no backup code issued')
    }
    const backup = await post(
      '/two-factor/verify-backup-code',
      { code, disableSession: true },
      session
    )
    expect(backup.status).toBe(200)
    bodies.push(await backup.text())

    for (const text of bodies) {
      const body = JSON.parse(text) as Record<string, unknown>
      expect(body).toMatchObject({ user: { email } })
      expect(body).not.toHaveProperty('token')
      expect(text).not.toContain(raw)
    }
  })

  it('the sign-in challenge body omits the minted token', async () => {
    const { email, secret } = await enrolledUser('redact-signin')
    const jar = await challenge(email)
    const verified = await verifyTotp(totpNow(secret), jar)
    expect(verified.status).toBe(200)
    const text = await verified.text()
    expect(JSON.parse(text)).not.toHaveProperty('token')
    expect(text).not.toContain(rawTokenOf(sessionCookieOf(verified)))
  })
})
