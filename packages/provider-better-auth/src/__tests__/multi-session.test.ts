/**
 * Multi-session logout (CAP-13b, spike S6): two users signed in on
 * one device through BA's `multiSession` plugin; one plugin logout
 * must revoke EVERY presented device session and expire every
 * presented multi cookie — no session may survive. Enumeration goes
 * through BA's verified `listDeviceSessions`, never cookie names.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { multiSession } from 'better-auth/plugins'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://multi.test'
const SECRET = 'multi-session-integration-secret!!'
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
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    plugins: [multiSession({ maximumSessions: 5 })],
  },
})

let config: SanitizedConfig
let payload: Payload

class Jar {
  private pairs = new Map<string, string>()

  store(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(';')
      const separator = pair?.indexOf('=') ?? -1
      if (pair === undefined || separator <= 0) {
        continue
      }
      const name = pair.slice(0, separator).trim()
      const value = pair.slice(separator + 1).trim()
      if (value === '') {
        this.pairs.delete(name)
      } else {
        this.pairs.set(name, value)
      }
    }
  }

  header(): string {
    return [...this.pairs.entries()].map(([name, value]) => `${name}=${value}`).join('; ')
  }

  names(): string[] {
    return [...this.pairs.keys()]
  }
}

function authRequest(path: string, body: unknown, cookie?: string): Request {
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method: 'POST',
    headers: {
      origin: ORIGIN,
      'content-type': 'application/json',
      ...(cookie === undefined ? {} : { cookie }),
    },
    body: JSON.stringify(body),
  })
}

async function signUp(email: string, jar: Jar): Promise<void> {
  const response = await engine.auth.handler(
    authRequest('/sign-up/email', { name: email, email, password: PASSWORD }, jar.header())
  )
  expect(response.status).toBe(200)
  jar.store(response)
  await payload.update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: { emailVerified: true },
    overrideAccess: true,
  })
}

async function signIn(email: string, jar: Jar): Promise<void> {
  const response = await engine.auth.handler(
    authRequest('/sign-in/email', { email, password: PASSWORD }, jar.header())
  )
  expect(response.status).toBe(200)
  jar.store(response)
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

describe('multi-session logout (CAP-13b)', () => {
  it('revokes every device session and expires every multi cookie', async () => {
    const jar = new Jar()
    await signUp('one@multi.test', jar)
    const jarTwo = new Jar()
    await signUp('two@multi.test', jarTwo)
    // Sign both in on ONE device jar: the second sign-in accumulates
    // a multi-session cookie beside the first.
    const device = new Jar()
    await signIn('one@multi.test', device)
    await signIn('two@multi.test', device)
    expect(device.names().some((name) => name.includes('_multi-'))).toBe(true)

    const listed = await engine.provider.listPresentedSessionIds?.(
      new Headers({ cookie: device.header() })
    )
    expect(listed?._unsafeUnwrap()).toHaveLength(2)
    const presentedCookies = engine.provider.presentedLogoutCookieNames?.(
      new Headers({ cookie: device.header() })
    )
    expect(presentedCookies?.length).toBeGreaterThanOrEqual(1)

    const cookie = device.header()
    const before = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(before.status).toBe(200)

    const logout = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, {
        method: 'DELETE',
        headers: { cookie, 'x-auth-link-csrf': '1' },
      }),
    })
    expect(logout.status).toBe(200)
    // Every presented multi cookie is expired by the response.
    const expired = logout.headers
      .getSetCookie()
      .map((entry) => entry.split('=', 1)[0])
      .filter((name): name is string => name !== undefined)
    for (const name of presentedCookies ?? []) {
      expect(expired).toContain(name)
    }

    // Neither device session survives: the provider reports none,
    // and the old cookies no longer verify.
    const afterList = await engine.provider.listPresentedSessionIds?.(new Headers({ cookie }))
    expect(afterList?._unsafeUnwrap()).toEqual([])
    const after = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(after.status).toBe(401)
  })
})
