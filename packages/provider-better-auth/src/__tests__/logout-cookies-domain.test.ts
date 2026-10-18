/**
 * Logout under `crossSubDomainCookies` (issue #113): Better Auth writes
 * every cookie with `Domain=<configured domain>`, so a clearing write
 * without that `Domain` names a DIFFERENT cookie and the browser keeps
 * the original. The cookie-cache `session_data` then keeps answering
 * BA's own `/get-session` (and everything that reads the cache) with
 * 200 after the plugin revoked the session server-side.
 *
 * A real engine signs in, a minimal RFC 6265 jar (cookies keyed by
 * name + domain + path) applies the sign-in and the plugin logout, and
 * the jar must be empty — and `/get-session` with whatever the browser
 * would still send must be signed out.
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
import { createBetterAuthEngine } from '../engine.js'

const DOMAIN = 'logout-domain.test'
const ORIGIN = `http://app.${DOMAIN}`
const SECRET = 'logout-domain-integration-secret!!!'
const PASSWORD = 'correct-horse-battery'

let latePayload: Payload | undefined
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    session: { cookieCache: { enabled: true, maxAge: 300 } },
    advanced: { crossSubDomainCookies: { enabled: true, domain: DOMAIN } },
  },
})

let config: SanitizedConfig
let payload: Payload

type JarEntry = { readonly value: string; readonly domain: string; readonly path: string }

/**
 * The browser side of RFC 6265 §5.3 the bug lives in: a cookie's
 * identity is (name, domain, path); a write without `Domain` is a
 * host-only cookie for the request host, a different cookie from a
 * `Domain=` one of the same name. `Max-Age=0` deletes the matching
 * cookie only.
 */
class CookieJar {
  private readonly entries = new Map<string, JarEntry & { readonly name: string }>()

  apply(response: Response, host: string): void {
    for (const raw of response.headers.getSetCookie()) {
      const [pair = '', ...attributes] = raw.split(';').map((part) => part.trim())
      const separator = pair.indexOf('=')
      const name = pair.slice(0, separator)
      const value = pair.slice(separator + 1)
      let domain = host
      let path = '/'
      let expired = false
      for (const attribute of attributes) {
        const [key = '', attributeValue = ''] = attribute.split('=')
        const lower = key.toLowerCase()
        if (lower === 'domain') {
          domain = `.${attributeValue.replace(/^\./, '')}`
        } else if (lower === 'path') {
          path = attributeValue
        } else if (lower === 'max-age' && Number(attributeValue) <= 0) {
          expired = true
        }
      }
      const key = `${name}|${domain}|${path}`
      if (expired) {
        this.entries.delete(key)
      } else {
        this.entries.set(key, { name, value, domain, path })
      }
    }
  }

  names(): string[] {
    return [...this.entries.values()].map((entry) => entry.name).sort()
  }

  header(): string {
    return [...this.entries.values()].map((entry) => `${entry.name}=${entry.value}`).join('; ')
  }
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

describe('logout with crossSubDomainCookies (issue #113)', () => {
  it('expires every cookie BA set under its Domain; BA get-session is signed out after', async () => {
    const email = 'domain@logout-domain.test'
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
    const host = new URL(ORIGIN).hostname
    const jar = new CookieJar()
    jar.apply(signIn, host)
    // BA really writes the cross-subdomain Domain on the cookies this
    // test is about.
    expect(jar.names()).toEqual(
      expect.arrayContaining([
        'better-auth.dont_remember',
        'better-auth.session_data',
        'better-auth.session_token',
      ])
    )
    for (const entry of signIn.headers.getSetCookie()) {
      expect(entry).toMatch(new RegExp(`;\\s*Domain=\\.?${DOMAIN.replace('.', '\\.')}`, 'i'))
    }
    // Precondition: the cookie cache answers BA's own get-session.
    const before = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/get-session`, { headers: { cookie: jar.header() } })
    )
    expect(before.status).toBe(200)
    expect(await before.json()).not.toBeNull()

    const logout = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        method: 'DELETE',
        headers: { cookie: jar.header(), 'x-auth-link-csrf': '1' },
      }),
    })
    expect(logout.status).toBe(200)
    jar.apply(logout, host)
    // Nothing BA set survives the plugin logout.
    expect(jar.names()).toEqual([])

    // What the browser still sends authenticates nothing at BA either
    // (with the residue, the cookie cache answered 200 with the user).
    const after = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/get-session`, { headers: { cookie: jar.header() } })
    )
    expect(after.status).toBe(200)
    expect(await after.json()).toBeNull()
  })
})
