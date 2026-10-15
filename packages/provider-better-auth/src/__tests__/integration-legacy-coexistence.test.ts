/**
 * Issue #51 acceptance: a user logged in under the payload-auth
 * fixture stays logged in across the switch — the legacy session
 * cookie is honored READ-ONLY inside the window and refused after it.
 * Real BA engine on in-memory SQLite; the legacy cookie is a
 * payload-auth-shaped name (`bl.session_token`) presented next to
 * (absent) current names.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'legacy-coexistence-secret-32ch'

let payload: Payload
let latePayload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (latePayload === undefined) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  // The window is OPEN until far future: the legacy name is honored.
  legacySessions: { until: '2099-01-01T00:00:00.000Z', cookieNames: ['bl.session_token'] },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: { enabled: false },
  },
})

/** Same engine shape, but the window CLOSED in the past. */
const closedEngine = createBetterAuthEngine({
  getPayload: () => {
    if (latePayload === undefined) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  legacySessions: { until: '2020-01-01T00:00:00.000Z', cookieNames: ['bl.session_token'] },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    rateLimit: { enabled: false },
  },
})

beforeAll(async () => {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
  })
  payload = await getPayload({ config })
  latePayload = payload
  await engine.auth.$context
  await closedEngine.auth.$context
}, 120_000)

describe('legacy session cookie coexistence (#51)', () => {
  it('honors the legacy cookie name inside the window (read-only translation)', async () => {
    await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-up/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({
          email: 'legacy@test.dev',
          password: 'Legacy-Passw0rd!',
          name: 'Legacy User',
        }),
      })
    )
    const signIn = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({ email: 'legacy@test.dev', password: 'Legacy-Passw0rd!' }),
      })
    )
    expect(signIn.status).toBe(200)
    const setCookie = signIn.headers.getSetCookie().find((c) => c.includes('session_token='))
    expect(setCookie).toBeDefined()
    const rawValue = setCookie?.split(';')[0]?.split('=')[1] ?? ''
    // Present the SAME live session under the LEGACY payload-auth name.
    const ctx = await engine.auth.$context
    void ctx
    const legacyHeaders = new Headers({
      cookie: `bl.session_token=${rawValue}`,
      origin: ORIGIN,
    })
    const port = engine.provider
    const found = await port.getSession(legacyHeaders)
    if (!found.isOk() || found.value === null) {
      throw new Error(found.isErr() ? found.error.message : 'legacy cookie did not resolve')
    }
    expect(found.value.email).toBe('legacy@test.dev')
    // Exposed for the cookie helpers / Edge middleware.
    expect(engine.legacySessionCookieNames).toEqual(['bl.session_token'])
  })

  it('mints new sessions only under the current cookie name', async () => {
    // The mint path (sessionCookie #54) uses the CURRENT name; the
    // legacy names never appear in Set-Cookie.
    const build = engine.provider.sessionCookie
    if (build === undefined) {
      throw new Error('the better-auth provider exposes no sessionCookie')
    }
    const cookie = await build('tok-1')
    expect(cookie).not.toContain('bl.session_token')
  })

  it('refuses the legacy cookie after the window closes', async () => {
    // Seed the user on the closed engine's shared payload storage.
    const closedSignIn = await closedEngine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({ email: 'legacy@test.dev', password: 'Legacy-Passw0rd!' }),
      })
    )
    const currentCookie = closedSignIn.headers
      .getSetCookie()
      .find((c) => c.includes('session_token='))
    const token = currentCookie?.split(';')[0]?.split('=')[1] ?? ''
    expect(token).toBeTruthy()
    const port = closedEngine.provider
    const currentNameHeaders = new Headers({
      cookie: `${port.sessionCookieNames[0]}=${token}`,
      origin: ORIGIN,
    })
    // Sanity: the CURRENT name still resolves after the window.
    const viaCurrent = await port.getSession(currentNameHeaders)
    expect(viaCurrent).not.toBeNull()
    // The legacy name is refused (translation dropped → session miss).
    const viaLegacy = await port.getSession(
      new Headers({ cookie: `bl.session_token=${token}`, origin: ORIGIN })
    )
    // Outside the window the legacy name is dropped: session miss.
    expect(viaLegacy.isOk() && viaLegacy.value === null).toBe(true)
  })
})
