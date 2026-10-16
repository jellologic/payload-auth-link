/**
 * Logout cookie residue: a real Better Auth engine with the cookie
 * cache on, a sign-in without "remember me" (BA's `dont_remember`
 * cookie), and a legacy coexistence window. One plugin logout must
 * expire every cookie BA set plus every name the configuration can
 * produce — including the `__Secure-` counterparts and the legacy
 * names.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { getBetterAuthLogoutCookieNames, getBetterAuthSessionCookieNames } from '../cookies.js'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://logout-cookies.test'
const SECRET = 'logout-cookies-integration-secret!!'
const PASSWORD = 'correct-horse-battery'
const legacyCookieNames = ['payload-auth.session_token']

let latePayload: Payload | undefined
const options = {
  baseURL: ORIGIN,
  trustedOrigins: [ORIGIN],
  secret: SECRET,
  emailAndPassword: { enabled: true, requireEmailVerification: false },
  session: { cookieCache: { enabled: true, maxAge: 300 } },
  account: { storeAccountCookie: true },
}
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  options,
  legacySessions: { until: '2999-01-01T00:00:00.000Z', cookieNames: legacyCookieNames },
})

let config: SanitizedConfig
let payload: Payload

function setCookieNames(response: Response): string[] {
  return response.headers
    .getSetCookie()
    .map((entry) => entry.split('=', 1)[0])
    .filter((name): name is string => name !== undefined && name !== '')
}

function cookieHeader(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((entry) => entry.split(';', 1)[0])
    .filter((pair): pair is string => pair !== undefined && !pair.endsWith('='))
    .join('; ')
}

function authRequest(path: string, body: unknown): Request {
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
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
      }),
    ],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
}, 120_000)

describe('logout cookie coverage', () => {
  it('expires every cookie BA set and every name the configuration can produce', async () => {
    const email = 'residue@logout-cookies.test'
    const signUp = await engine.auth.handler(
      authRequest('/sign-up/email', { name: email, email, password: PASSWORD })
    )
    expect(signUp.status).toBe(200)
    await payload.update({
      collection: 'ba-users',
      where: { email: { equals: email } },
      data: { emailVerified: true },
      overrideAccess: true,
    })
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', { email, password: PASSWORD, rememberMe: false })
    )
    expect(signIn.status).toBe(200)
    const set = setCookieNames(signIn)
    // The residue this suite exists for is really produced.
    expect(set).toContain('better-auth.dont_remember')
    expect(set).toContain('better-auth.session_data')

    const cookie = `${cookieHeader(signIn)}; ${legacyCookieNames[0] ?? ''}=stale`
    const logout = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        method: 'DELETE',
        headers: { cookie, 'x-auth-link-csrf': '1' },
      }),
    })
    expect(logout.status).toBe(200)
    const expired = setCookieNames(logout)
    const expected = [
      ...set,
      ...getBetterAuthSessionCookieNames(options),
      ...getBetterAuthLogoutCookieNames(options),
      ...legacyCookieNames,
      '__Secure-better-auth.session_token',
      '__Secure-better-auth.session_data',
      '__Secure-better-auth.dont_remember',
    ]
    for (const name of expected) {
      expect(expired).toContain(name)
    }
    for (const entry of logout.headers.getSetCookie()) {
      expect(entry).toMatch(/Max-Age=0/)
    }
  })

  it('expires every presented cookie-cache and account cookie chunk (#110)', async () => {
    const email = 'chunked@logout-cookies.test'
    // A user payload far over BA's 4050-byte per-cookie ceiling forces
    // the cookie cache to split `session_data` into numbered chunks.
    const name = 'n'.repeat(9_000)
    const signUp = await engine.auth.handler(
      authRequest('/sign-up/email', { name, email, password: PASSWORD })
    )
    expect(signUp.status).toBe(200)
    await payload.update({
      collection: 'ba-users',
      where: { email: { equals: email } },
      data: { emailVerified: true },
      overrideAccess: true,
    })
    const signIn = await engine.auth.handler(
      authRequest('/sign-in/email', { email, password: PASSWORD })
    )
    expect(signIn.status).toBe(200)
    const set = setCookieNames(signIn)
    const chunks = set.filter((cookie) => /^better-auth\.session_data\.\d+$/.test(cookie))
    // The residue this test exists for is really produced by BA.
    expect(chunks).toEqual(
      expect.arrayContaining(['better-auth.session_data.0', 'better-auth.session_data.1'])
    )
    expect(set).not.toContain('better-auth.session_data')

    // Chunks a browser may also hold: the account cookie cache
    // (`storeAccountCookie`) and leftovers under the other `__Secure-`
    // setting from an http→https switch.
    const residue = [
      'better-auth.account_data.0',
      'better-auth.account_data.1',
      '__Secure-better-auth.session_data.0',
      '__Secure-better-auth.session_data.1',
      '__Secure-better-auth.account_data.0',
    ]
    const cookie = [cookieHeader(signIn), ...residue.map((n) => `${n}=stale`)].join('; ')
    const logout = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        method: 'DELETE',
        headers: { cookie, 'x-auth-link-csrf': '1' },
      }),
    })
    expect(logout.status, await logout.clone().text()).toBe(200)
    const entries = logout.headers.getSetCookie()
    const expired = setCookieNames(logout)
    for (const chunk of [...chunks, ...residue]) {
      expect(expired).toContain(chunk)
    }
    for (const unsuffixed of [
      'better-auth.session_data',
      'better-auth.account_data',
      '__Secure-better-auth.session_data',
      '__Secure-better-auth.account_data',
    ]) {
      expect(expired).toContain(unsuffixed)
    }
    for (const entry of entries) {
      expect(entry).toMatch(/Max-Age=0/)
    }
    // `__Secure-` chunks must be cleared with `Secure`, or the browser
    // ignores the overwrite.
    for (const entry of entries.filter((e) => e.startsWith('__Secure-'))) {
      expect(entry).toMatch(/;\s*Secure/i)
    }
  })
})
