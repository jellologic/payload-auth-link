/**
 * Capability integration (CAP-1/2/6/7/9/10): one real Better Auth
 * engine — magicLink, emailOTP, anonymous, phoneNumber, twoFactor —
 * on real Payload storage (SQLite in memory), bridged by the plugin
 * with `requireMfaForRoles` and the verified-email-or-phone linking
 * policy wired. Each capability is proven end to end: provider flow
 * → port facts → plugin session endpoint → Payload user state. All
 * mail/SMS are captured in-process; TOTP codes are computed from the
 * enrollment secret (no third-party service anywhere).
 */
import { createHmac } from 'node:crypto'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { getAuthTables } from 'better-auth/db'
import { anonymous, emailOTP, magicLink, phoneNumber, twoFactor } from 'better-auth/plugins'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { generateDeclarations } from './declarations.js'

const ORIGIN = 'http://capabilities.test'
const SECRET = 'capabilities-integration-secret!!!'
const PASSWORD = 'correct-horse-battery'

const sentMagicLinks: { email: string; url: string }[] = []
const sentEmailOtps: { email: string; otp: string }[] = []
const sentPhoneOtps: { phoneNumber: string; code: string }[] = []

const plugins = [
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
  anonymous(),
  phoneNumber({
    sendOTP: ({ phoneNumber: target, code }) => {
      sentPhoneOtps.push({ phoneNumber: target, code })
      return Promise.resolve()
    },
    signUpOnVerification: {
      getTempEmail: (target) => `${target.replaceAll('+', '')}@phone.capabilities.test`,
      getTempName: (target) => target,
    },
  }),
  twoFactor(),
]

const engineOptions = {
  baseURL: ORIGIN,
  trustedOrigins: [ORIGIN],
  secret: SECRET,
  emailAndPassword: { enabled: true, requireEmailVerification: false },
  plugins,
}

const declarations = generateDeclarations(getAuthTables(engineOptions))

let latePayload: Payload | undefined
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  customFields: declarations.customFields,
  customModels: declarations.customModels,
  options: engineOptions,
})

let config: SanitizedConfig
let payload: Payload

function cookieHeaderFrom(response: Response): string {
  const jar = new Map<string, string>()
  for (const entry of response.headers.getSetCookie()) {
    const pair = entry.split(';', 1)[0]
    if (pair === undefined || pair === '') {
      continue
    }
    const name = pair.split('=', 1)[0]
    if (name !== undefined && name !== '') {
      jar.set(name, pair)
    }
  }
  return [...jar.values()].join('; ')
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

async function pluginSession(cookie: string): Promise<Response> {
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
  })
}

async function sessionBody(response: Response): Promise<{
  user: { id: unknown; email: string; roles: string[]; mfaRequired?: boolean } | null
  guest?: { id: string; providerId: string }
}> {
  return (await response.json()) as {
    user: { id: unknown; email: string; roles: string[]; mfaRequired?: boolean } | null
    guest?: { id: string; providerId: string }
  }
}

async function signUpVerified(
  email: string,
  name: string
): Promise<{ baUserId: string; cookie: string }> {
  const response = await engine.auth.handler(
    authRequest('/sign-up/email', { method: 'POST', body: { name, email, password: PASSWORD } })
  )
  expect(response.status).toBe(200)
  const body = (await response.json()) as { user?: { id?: unknown } }
  if (typeof body.user?.id !== 'string') {
    throw new Error('sign-up returned no user id')
  }
  await payload.update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: true },
    overrideAccess: true,
  })
  return { baUserId: body.user.id, cookie: cookieHeaderFrom(response) }
}

/** RFC 6238 TOTP (SHA-1, 30s step, 6 digits) for a base32 secret. */
function totp(base32Secret: string, at = new Date()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of base32Secret.replaceAll('=', '').toUpperCase()) {
    const value = alphabet.indexOf(char)
    if (value === -1) {
      throw new Error(`invalid base32 character ${char}`)
    }
    bits += value.toString(2).padStart(5, '0')
  }
  const keyBytes: number[] = []
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    keyBytes.push(Number.parseInt(bits.slice(index, index + 8), 2))
  }
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at.getTime() / 1000 / 30)))
  const digest = createHmac('sha1', Buffer.from(keyBytes)).update(counter).digest()
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f
  const binary =
    ((digest[offset] ?? 0) & 0x7f) * 2 ** 24 +
    (digest[offset + 1] ?? 0) * 2 ** 16 +
    (digest[offset + 2] ?? 0) * 2 ** 8 +
    (digest[offset + 3] ?? 0)
  return String(binary % 1_000_000).padStart(6, '0')
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [engine.provider],
        linkingPolicy: { kind: 'verified-email-or-phone' },
        policies: { requireMfaForRoles: ['admin'] },
      }),
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
}, 120_000)

describe('engine capability declaration (PORT-2)', () => {
  it('declares exactly the installed plugins capabilities plus revoke-user-sessions', () => {
    expect([...engine.provider.capabilities].sort()).toEqual(
      [
        'anonymous',
        'email-otp',
        'magic-link',
        'mfa',
        'phone',
        'revoke-user-sessions',
        'server-session-create',
        'server-session-list',
      ].sort()
    )
  })
})

describe('CAP-1 magic link (Better Auth)', () => {
  it('signs in via a captured link and the plugin provisions the Payload user', async () => {
    const email = 'magic@capabilities.test'
    const requested = await engine.auth.handler(
      authRequest('/sign-in/magic-link', {
        method: 'POST',
        body: { email, callbackURL: '/account' },
      })
    )
    expect(requested.status).toBe(200)
    const sent = sentMagicLinks.find((entry) => entry.email === email)
    if (sent === undefined) {
      throw new Error('magic link was not captured')
    }
    // Follow the exact URL BA handed the mailer (path + query on our origin).
    const link = new URL(sent.url)
    const verifyPath = `${link.pathname.replace(/^\/api\/auth/, '')}${link.search}`
    const verified = await engine.auth.handler(authRequest(verifyPath))
    const cookie = cookieHeaderFrom(verified)
    expect(cookie).toContain('better-auth.session_token=')
    const portSession = (await engine.provider.getSession(new Headers({ cookie })))._unsafeUnwrap()
    expect(portSession?.identity.email).toEqual({ value: email, verified: true })

    const response = await pluginSession(cookie)
    expect(response.status).toBe(200)
    const body = await sessionBody(response)
    expect(body.user?.email).toBe(email)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: email } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(1)

    // Single use: replaying the same link must not mint a session.
    const replay = await engine.auth.handler(authRequest(verifyPath))
    expect(cookieHeaderFrom(replay)).not.toContain('better-auth.session_token=')
  })
})

describe('CAP-2 email OTP (Better Auth)', () => {
  it('signs in with a captured code; a wrong code does not', async () => {
    const email = 'otp@capabilities.test'
    await signUpVerified(email, 'Otp User')
    const sentResponse = await engine.auth.handler(
      authRequest('/email-otp/send-verification-otp', {
        method: 'POST',
        body: { email, type: 'sign-in' },
      })
    )
    expect(sentResponse.status).toBe(200)
    const sent = sentEmailOtps.find((entry) => entry.email === email)
    if (sent === undefined) {
      throw new Error('email OTP was not captured')
    }
    const wrong = sent.otp === '000000' ? '999999' : '000000'
    const refused = await engine.auth.handler(
      authRequest('/sign-in/email-otp', { method: 'POST', body: { email, otp: wrong } })
    )
    expect(refused.status).not.toBe(200)
    const accepted = await engine.auth.handler(
      authRequest('/sign-in/email-otp', { method: 'POST', body: { email, otp: sent.otp } })
    )
    expect(accepted.status).toBe(200)
    const cookie = cookieHeaderFrom(accepted)
    const response = await pluginSession(cookie)
    expect(response.status).toBe(200)
    expect((await sessionBody(response)).user?.email).toBe(email)
  })
})

describe('CAP-2/CAP-18 OTP attempt cap (Better Auth native)', () => {
  it('burns the code after 3 wrong guesses: the correct code is then refused', async () => {
    const email = 'otp-capped@capabilities.test'
    await signUpVerified(email, 'Capped User')
    const sentResponse = await engine.auth.handler(
      authRequest('/email-otp/send-verification-otp', {
        method: 'POST',
        body: { email, type: 'sign-in' },
      })
    )
    expect(sentResponse.status).toBe(200)
    const sent = sentEmailOtps.find((entry) => entry.email === email)
    if (sent === undefined) {
      throw new Error('email OTP was not captured')
    }
    const wrong = sent.otp === '000000' ? '999999' : '000000'
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const refused = await engine.auth.handler(
        authRequest('/sign-in/email-otp', { method: 'POST', body: { email, otp: wrong } })
      )
      expect(refused.status).not.toBe(200)
    }
    // BA counts attempts per identifier (default cap 3): past the
    // cap even the genuine code is dead (TOO_MANY_ATTEMPTS).
    const burned = await engine.auth.handler(
      authRequest('/sign-in/email-otp', { method: 'POST', body: { email, otp: sent.otp } })
    )
    expect(burned.status).not.toBe(200)
    expect(cookieHeaderFrom(burned)).not.toContain('better-auth.session_token=')
  })
})

describe('CAP-10 anonymous guest (D3)', () => {
  it('reports a guest principal, never a Payload user', async () => {
    const before = await payload.count({ collection: 'users', overrideAccess: true })
    const response = await engine.auth.handler(
      authRequest('/sign-in/anonymous', { method: 'POST', body: {} })
    )
    expect(response.status).toBe(200)
    const cookie = cookieHeaderFrom(response)
    const portSession = (await engine.provider.getSession(new Headers({ cookie })))._unsafeUnwrap()
    expect(portSession?.identity.anonymous).toBe(true)
    expect(portSession?.identity.email).toBeNull()

    // Payload's own auth (the strategy) also yields no user: a guest
    // has no Payload access anywhere, not just at our endpoint.
    const strategyResult = await payload.auth({ headers: new Headers({ cookie }) })
    expect(strategyResult.user).toBeNull()

    const sessionResponse = await pluginSession(cookie)
    expect(sessionResponse.status).toBe(200)
    const body = await sessionBody(sessionResponse)
    expect(body.user).toBeNull()
    expect(body.guest?.providerId).toBe('better-auth')
    expect(body.guest?.id).toBe(portSession?.providerUserId)
    const after = await payload.count({ collection: 'users', overrideAccess: true })
    expect(after.totalDocs).toBe(before.totalDocs)
  })
})

describe('CAP-9 phone number (D2)', () => {
  const phone = '+14155550101'

  it('links a phone OTP sign-in to the existing Payload user holding the number', async () => {
    const email = 'phone@capabilities.test'
    const { cookie } = await signUpVerified(email, 'Phone User')
    // First touch provisions the Payload user.
    const first = await pluginSession(cookie)
    expect(first.status).toBe(200)
    const payloadUserId = (await sessionBody(first)).user?.id
    // The number lands on both sides: BA user (provider claim source)
    // and Payload user (link target). In product code the BA value is
    // set by BA's own phone verification; here it is seeded directly.
    await payload.update({
      collection: 'ba-users',
      where: { email: { equals: email } },
      data: { phoneNumber: phone, phoneNumberVerified: true },
      overrideAccess: true,
    })
    await payload.update({
      collection: 'users',
      where: { email: { equals: email } },
      data: { phone },
      overrideAccess: true,
    })

    const sentResponse = await engine.auth.handler(
      authRequest('/phone-number/send-otp', { method: 'POST', body: { phoneNumber: phone } })
    )
    expect(sentResponse.status).toBe(200)
    const sent = sentPhoneOtps.find((entry) => entry.phoneNumber === phone)
    if (sent === undefined) {
      throw new Error('phone OTP was not captured')
    }
    const verified = await engine.auth.handler(
      authRequest('/phone-number/verify', {
        method: 'POST',
        body: { phoneNumber: phone, code: sent.code },
      })
    )
    expect(verified.status).toBe(200)
    const phoneCookie = cookieHeaderFrom(verified)
    const portSession = (
      await engine.provider.getSession(new Headers({ cookie: phoneCookie }))
    )._unsafeUnwrap()
    expect(portSession?.identity.phone).toEqual({ value: phone, verified: true })

    const response = await pluginSession(phoneCookie)
    expect(response.status).toBe(200)
    expect((await sessionBody(response)).user?.id).toBe(payloadUserId)
  })

  it('refuses a phone-only sign-up: verified phone never provisions (D2)', async () => {
    const soloPhone = '+14155550102'
    await engine.auth.handler(
      authRequest('/phone-number/send-otp', { method: 'POST', body: { phoneNumber: soloPhone } })
    )
    const sent = sentPhoneOtps.find((entry) => entry.phoneNumber === soloPhone)
    if (sent === undefined) {
      throw new Error('phone OTP was not captured')
    }
    const verified = await engine.auth.handler(
      authRequest('/phone-number/verify', {
        method: 'POST',
        body: { phoneNumber: soloPhone, code: sent.code },
      })
    )
    expect(verified.status).toBe(200)
    const response = await pluginSession(cookieHeaderFrom(verified))
    expect(response.status).toBe(401)
    const stored = await payload.find({
      collection: 'users',
      where: { phone: { equals: soloPhone } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(0)
  })
})

describe('CAP-6 two-factor + requireMfaForRoles', () => {
  it('withholds admin without MFA enrollment and restores it after TOTP enrollment', async () => {
    const email = 'mfa@capabilities.test'
    const { cookie } = await signUpVerified(email, 'Mfa User')
    const first = await pluginSession(cookie)
    expect(first.status).toBe(200)
    await payload.update({
      collection: 'users',
      where: { email: { equals: email } },
      data: { roles: ['admin', 'user'] },
      overrideAccess: true,
    })

    const gated = await sessionBody(await pluginSession(cookie))
    expect(gated.user?.roles).toEqual(['user'])
    expect(gated.user?.mfaRequired).toBe(true)

    const enabled = await engine.auth.handler(
      authRequest('/two-factor/enable', {
        method: 'POST',
        body: { password: PASSWORD },
        cookie,
      })
    )
    expect(enabled.status).toBe(200)
    const enabledBody = (await enabled.json()) as { totpURI?: unknown }
    if (typeof enabledBody.totpURI !== 'string') {
      throw new Error('two-factor enable returned no totpURI')
    }
    const secret = new URL(enabledBody.totpURI).searchParams.get('secret')
    if (secret === null) {
      throw new Error('totpURI carries no secret')
    }
    const verifiedTotp = await engine.auth.handler(
      authRequest('/two-factor/verify-totp', {
        method: 'POST',
        body: { code: totp(secret) },
        cookie,
      })
    )
    expect(verifiedTotp.status).toBe(200)
    // TOTP verification rotates the session: use the fresh cookie.
    const mfaCookie = cookieHeaderFrom(verifiedTotp) || cookie

    // Enrollment is not proof (the server-session advisory fix): the
    // signed-in session records no method, so it still proves nothing
    // and admin stays withheld — even with twoFactorEnabled now true.
    const portSession = (
      await engine.provider.getSession(new Headers({ cookie: mfaCookie }))
    )._unsafeUnwrap()
    expect(portSession?.assurance.mfa).toBe('unknown')
    const stillGated = await sessionBody(await pluginSession(mfaCookie))
    expect(stillGated.user?.roles).toEqual(['user'])
    expect(stillGated.user?.mfaRequired).toBe(true)

    // The server verified the TOTP itself, so it may VOUCH the step-up:
    // a minted session with the server-vouched proof records the
    // method, and the gate restores admin.
    const found = await payload.find({
      collection: 'ba-users',
      where: { email: { equals: email } },
      limit: 1,
      overrideAccess: true,
    })
    const baUserId = (found.docs[0] as { baId?: unknown } | undefined)?.baId
    if (typeof baUserId !== 'string') {
      throw new Error('no ba-users row for the enrolled user')
    }
    const createSession = engine.provider.createProviderSession
    if (createSession === undefined) {
      throw new Error('the better-auth provider cannot mint sessions')
    }
    const created = await createSession(baUserId, {
      expiresAt: new Date(Date.now() + 3_600_000),
      mfaProof: true,
    })
    if (created.isErr()) {
      throw new Error(created.error.message)
    }
    const buildCookie = engine.provider.sessionCookie
    if (buildCookie === undefined) {
      throw new Error('the better-auth provider exposes no sessionCookie')
    }
    const stepUpCookie = await buildCookie(created.value.token)
    const portStepUp = (
      await engine.provider.getSession(new Headers({ cookie: stepUpCookie }))
    )._unsafeUnwrap()
    expect(portStepUp?.assurance.mfa).toBe(true)
    expect(portStepUp?.assurance.methods).toEqual(['server-step-up'])
    const restored = await sessionBody(await pluginSession(stepUpCookie))
    expect(restored.user?.roles).toEqual(['admin', 'user'])
    expect(restored.user?.mfaRequired).toBeUndefined()
  })
})

describe('CAP-7 suspend (Payload-governed)', () => {
  it('refuses the next verify and revokes the provider sessions', async () => {
    const email = 'suspended@capabilities.test'
    const { cookie } = await signUpVerified(email, 'Suspended User')
    expect((await pluginSession(cookie)).status).toBe(200)

    await payload.update({
      collection: 'users',
      where: { email: { equals: email } },
      data: {
        suspendedUntil: new Date(Date.now() + 3600_000).toISOString(),
        suspendReason: 'integration test',
      },
      overrideAccess: true,
    })

    // The suspend hook revoked BA-side sessions (best-effort layer)…
    const portSession = (await engine.provider.getSession(new Headers({ cookie })))._unsafeUnwrap()
    expect(portSession).toBeNull()
    // …and the plugin refuses regardless (the authoritative gate).
    expect((await pluginSession(cookie)).status).toBe(401)

    // Lifting the suspension readmits a fresh sign-in.
    await payload.update({
      collection: 'users',
      where: { email: { equals: email } },
      data: { suspendedUntil: null },
      overrideAccess: true,
    })
    const signedIn = await engine.auth.handler(
      authRequest('/sign-in/email', { method: 'POST', body: { email, password: PASSWORD } })
    )
    expect(signedIn.status).toBe(200)
    expect((await pluginSession(cookieHeaderFrom(signedIn))).status).toBe(200)
  })
})
