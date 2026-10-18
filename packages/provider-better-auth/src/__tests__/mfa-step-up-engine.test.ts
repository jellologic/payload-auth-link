/**
 * GHSA-38wx-69j6-cgm7 — MFA step-up on an EXISTING session, on a real
 * Better Auth 1.7 engine (twoFactor with TOTP, backup codes and an
 * emailed OTP; magicLink; emailOTP) on real Payload storage (SQLite
 * in memory) behind a real `authLink` boot with
 * `requireMfaForRoles: ['admin']`.
 *
 * Since #110 a correct second factor on an existing session relabels
 * it `two-factor`. Better Auth itself counts failed codes and locks
 * the account only on the sign-in challenge path, and its enrolment
 * confirmation is itself a "correct second factor on a session". Each
 * test below fails without the step-up guard (step-up.ts):
 *
 * - wrong step-up codes spend the shared failure budget, the account
 *   locks, and a correct code is refused (429) while it is locked —
 *   on the step-up AND the sign-in path, whichever spent the budget;
 * - enrolling the FIRST factor on a password session (all a
 *   password-only attacker can do) does not make it MFA-proven, so
 *   the MFA-gated role stays withheld;
 * - a step-up with an already-enrolled factor still relabels;
 * - an emailed two-factor OTP is not a second factor after an
 *   inbox-based first factor (magic link, email OTP) by default.
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
/** Better Auth's default `accountLockout.maxFailedAttempts`. */
const MAX_FAILED = 10

const sentTwoFactorOtps: { email: string; otp: string }[] = []
const sentMagicLinks: { email: string; url: string }[] = []
const sentEmailOtps: { email: string; otp: string }[] = []

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
    emailAndPassword: { enabled: true, requireEmailVerification: false },
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
async function enrolledUser(
  prefix: string
): Promise<{ email: string; userId: string; secret: string; cookie: string }> {
  const email = uniqueEmail(prefix)
  const userId = await signUp(email)
  const first = await passwordSession(email)
  const { secret } = await enable(first)
  const confirmed = await verifyTotp(totpNow(secret), first)
  expect(confirmed.status, `enroll: ${await confirmed.clone().text()}`).toBe(200)
  return { email, userId, secret, cookie: sessionCookieOf(confirmed) }
}

type CounterRow = { failedVerificationCount?: unknown; lockedUntil?: unknown; id?: unknown }

async function counterOf(userId: string): Promise<CounterRow> {
  const ctx = await engine.auth.$context
  const row = await ctx.adapter.findOne<CounterRow>({
    model: 'twoFactor',
    where: [{ field: 'userId', value: userId }],
  })
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
    const challenge = await post('/sign-in/email', { email, password: PASSWORD })
    expect(((await challenge.json()) as { twoFactorRedirect?: unknown }).twoFactorRedirect).toBe(
      true
    )
    const signIn = await verifyTotp(totpNow(secret), cookieJarOf(challenge))
    expect(signIn.status).toBe(429)
    expect(sessionCookieOrNull(signIn)).toBeNull()
  })

  it('a lock spent on the sign-in path refuses a correct step-up', async () => {
    const { email, secret, cookie } = await enrolledUser('lockout-signin')
    // BA burns a sign-in challenge after 5 attempts: spend the budget
    // across two challenges.
    for (let challengeIndex = 0; challengeIndex < MAX_FAILED / 5; challengeIndex += 1) {
      const challenge = await post('/sign-in/email', { email, password: PASSWORD })
      const jar = cookieJarOf(challenge)
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
    const { userId, secret, cookie } = await enrolledUser('lockout-expired')
    await spendWrongStepUps(secret, cookie, MAX_FAILED)
    await setLockedUntil(userId, new Date(Date.now() - 1000))
    const verified = await verifyTotp(totpNow(secret), cookie)
    expect(verified.status).toBe(200)
    expect((await assuranceOf(cookie)).methods).toEqual(['two-factor'])
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
})

describe('enrolling the first factor is not MFA proof for that session', () => {
  it('a password-only attacker enrolling their own TOTP does not unlock the MFA-gated role', async () => {
    const email = uniqueEmail('attacker-totp')
    await signUp(email)
    // The victim holds an MFA-gated role and never enrolled 2FA.
    const attacker = await passwordSession(email)
    await grantAdmin(email, attacker)
    expect(await pluginRoles(attacker)).toEqual({ roles: ['user'], mfaRequired: true })

    // The attacker knows only the password: enable, then confirm with
    // THEIR authenticator.
    const { secret } = await enable(attacker)
    const confirmed = await verifyTotp(totpNow(secret), attacker)
    expect(confirmed.status).toBe(200)
    // BA rotates the session; the rotated one keeps the password label.
    const rotated = sessionCookieOf(confirmed)
    expect(await assuranceOf(rotated)).toEqual({ methods: ['password'], mfa: false })
    expect(await pluginRoles(rotated)).toEqual({ roles: ['user'], mfaRequired: true })
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

  it('a step-up with the already-enrolled factor still relabels the session', async () => {
    const { cookie, secret } = await enrolledUser('enrolled-stepup')
    // The enrolment session (rotated) still reads single-factor…
    expect(await assuranceOf(cookie)).toEqual({ methods: ['password'], mfa: false })
    // …until a verification with the factor enrolled BEFORE it.
    const verified = await verifyTotp(totpNow(secret), cookie)
    expect(verified.status).toBe(200)
    expect(await assuranceOf(cookie)).toEqual({ methods: ['two-factor'], mfa: true })
  })
})

describe('an emailed two-factor OTP after an inbox-based first factor (default)', () => {
  async function stepUpWithEmailedOtp(email: string, cookie: string): Promise<void> {
    const sent = await post('/two-factor/send-otp', {}, cookie)
    expect(sent.status).toBe(200)
    const otp = sentTwoFactorOtps.findLast((entry) => entry.email === email)?.otp
    if (otp === undefined) {
      throw new Error('two-factor OTP was not captured')
    }
    const verified = await post('/two-factor/verify-otp', { code: otp }, cookie)
    expect(verified.status, `verify-otp: ${await verified.clone().text()}`).toBe(200)
  }

  it('does not make a magic-link session MFA-proven; TOTP still does', async () => {
    const { email, secret } = await enrolledUser('inbox-magic')
    const requested = await post('/sign-in/magic-link', { email, callbackURL: '/account' })
    expect(requested.status).toBe(200)
    const link = sentMagicLinks.findLast((entry) => entry.email === email)
    if (link === undefined) {
      throw new Error('magic link was not captured')
    }
    // Without a callbackURL BA answers the verification with a 200
    // body (the redirect variant records no method at all, which
    // proves nothing either way).
    const url = new URL(link.url)
    url.searchParams.delete('callbackURL')
    const followed = await engine.auth.handler(
      authRequest(`${url.pathname.replace(/^\/api\/auth/, '')}${url.search}`)
    )
    const magic = sessionCookieOf(followed)
    expect((await assuranceOf(magic)).methods).toEqual(['magic-link'])

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

  it('does relabel a password session (password + inbox are two factors)', async () => {
    const { email, cookie } = await enrolledUser('inbox-password')
    await stepUpWithEmailedOtp(email, cookie)
    expect(await assuranceOf(cookie)).toEqual({ methods: ['two-factor'], mfa: true })
  })
})
