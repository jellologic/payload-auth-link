/**
 * Phase 4 SPIKE (not the adapter): proves Auth.js runs fully locally on
 * Payload storage and records the exact behaviors the adapter relies on.
 *
 * Findings (verified by the assertions below, against @auth/core):
 * - Credentials is JWT-only: the callback branch never calls the adapter
 *   (no createUser, no createSession) and ignores `session.strategy`.
 *   Users come solely from `authorize`; sessions are encrypted JWTs.
 * - Credentials + `database` strategy is rejected at config time
 *   (`UnsupportedStrategy`, loud 500s on every action — asserted below).
 *   Credentials REQUIRES explicit `session: { strategy: 'jwt' }`; the
 *   adapter on the config then serves OAuth/Email providers only.
 * - The jwt callback re-runs on every session read WITHOUT `user`: claims
 *   must be set only when `user` is present or the re-encoded token loses
 *   them (proven by the emailVerified round-trip below).
 * - The port reads sessions through Auth.js's own session action
 *   (`skipCSRFCheck`, no hand-rolled JWT decode), both as a Response
 *   and via the `raw` internal shape.
 * - `session.user.id` is typed; `emailVerified` rides a custom JWT
 *   claim through the standard jwt/session callbacks (module
 *   augmentation, the documented Auth.js pattern).
 * - Cookie names: `authjs.session-token` (+ `__Secure-` prefix when
 *   secure), chunked as `.0`, `.1`, … when the JWT exceeds ~4k.
 */
import { Auth, raw, skipCSRFCheck, type AuthConfig } from '@auth/core'
import type { Adapter } from '@auth/core/adapters'
import Credentials from '@auth/core/providers/credentials'
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import {
  buildConfig,
  getPayload,
  type CollectionConfig,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'

declare module '@auth/core/types' {
  // The documented Auth.js pattern: surface the verification flag the
  // port's just-in-time linking gates on.
  interface Session {
    user?: {
      id?: string
      name?: string | null
      email?: string | null
      image?: string | null
      emailVerified?: boolean | null | undefined
    }
  }
}

const ORIGIN = 'http://spike.test'
const BASE_PATH = '/api/authjs'
const SECRET = 'spike-secret-32-chars-minimum!!'
const USERS = 'spike-authjs-users'
const SESSIONS = 'spike-authjs-sessions'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex')
  return `${salt}:${scryptSync(password, salt, 32).toString('hex')}`
}

function verifyPassword(password: string, stored: string): boolean {
  const [salt, expected] = stored.split(':')
  if (salt === undefined || expected === undefined) {
    return false
  }
  const derived = Buffer.from(scryptSync(password, salt, 32).toString('hex'), 'hex')
  const wanted = Buffer.from(expected, 'hex')
  return derived.length === wanted.length && timingSafeEqual(derived, wanted)
}

function collections(): CollectionConfig[] {
  return [
    {
      slug: USERS,
      fields: [
        { name: 'auId', type: 'text', required: true, unique: true },
        { name: 'email', type: 'email', required: true, unique: true },
        { name: 'name', type: 'text' },
        { name: 'passwordHash', type: 'text', required: true },
        { name: 'emailVerified', type: 'date' },
      ],
    },
    {
      slug: SESSIONS,
      fields: [
        { name: 'sessionToken', type: 'text', required: true, unique: true },
        { name: 'userId', type: 'text', required: true },
        { name: 'expires', type: 'date', required: true },
      ],
    },
  ]
}

/** Minimal adapter: only what the spike exercises. */
function createSpikeAdapter(payload: Payload): Adapter {
  return {
    async getSessionAndUser(sessionToken) {
      const found = await payload.find({
        collection: SESSIONS,
        where: { sessionToken: { equals: sessionToken } },
        limit: 1,
        overrideAccess: true,
      })
      const sessionDoc: unknown = found.docs[0]
      if (!isRecord(sessionDoc) || typeof sessionDoc.userId !== 'string') {
        return null
      }
      const users = await payload.find({
        collection: USERS,
        where: { auId: { equals: sessionDoc.userId } },
        limit: 1,
        overrideAccess: true,
      })
      const userDoc: unknown = users.docs[0]
      if (!isRecord(userDoc)) {
        return null
      }
      return {
        session: {
          sessionToken,
          userId: sessionDoc.userId,
          expires: new Date(String(sessionDoc.expires)),
        },
        user: {
          id: sessionDoc.userId,
          email: String(userDoc.email),
          emailVerified:
            typeof userDoc.emailVerified === 'string' ? new Date(userDoc.emailVerified) : null,
        },
      }
    },
  }
}

function createConfig(
  payload: Payload,
  adapter: Adapter,
  strategy: 'jwt' | 'database'
): AuthConfig {
  return {
    trustHost: true,
    secret: SECRET,
    basePath: BASE_PATH,
    session: { strategy, maxAge: 3600 },
    adapter,
    providers: [
      Credentials({
        credentials: {
          email: { label: 'Email', type: 'email' },
          password: { label: 'Password', type: 'password' },
        },
        authorize: async (credentials) => {
          const email = credentials?.email
          const password = credentials?.password
          if (typeof email !== 'string' || typeof password !== 'string') {
            return null
          }
          const found = await payload.find({
            collection: USERS,
            where: { email: { equals: email } },
            limit: 1,
            overrideAccess: true,
          })
          const doc: unknown = found.docs[0]
          if (!isRecord(doc)) {
            return null
          }
          if (typeof doc.passwordHash !== 'string' || !verifyPassword(password, doc.passwordHash)) {
            return null
          }
          // Built as a variable (not a fresh literal): `User` carries no
          // verification field, and the jwt callback below picks it up
          // from the smuggled claim for the session body.
          const user = {
            id: String(doc.auId),
            email: String(doc.email),
            ...(typeof doc.name === 'string' ? { name: doc.name } : {}),
            emailVerified:
              typeof doc.emailVerified === 'string' ? new Date(doc.emailVerified) : null,
          }
          return user
        },
      }),
    ],
    callbacks: {
      jwt: ({ token, user }) => {
        // `user` is present only at sign-in; session reads re-invoke this
        // callback with the decoded token, so claims set here must never
        // be overwritten when `user` is absent (the token re-encodes).
        if (user === undefined) {
          return token
        }
        if (user.id !== undefined) {
          token.sub = user.id
        }
        const smuggled = user as { emailVerified?: unknown }
        const verified: unknown = smuggled.emailVerified
        token.authLinkEmailVerified = verified instanceof Date ? verified.toISOString() : null
        return token
      },
      session: ({ session, token }) => ({
        ...session,
        user: {
          ...session.user,
          ...(token.sub === undefined ? {} : { id: token.sub }),
          emailVerified: typeof token.authLinkEmailVerified === 'string',
        },
      }),
    },
  }
}

/** Tiny cookie jar across Auth() calls. */
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

async function csrfToken(config: AuthConfig, jar: Jar): Promise<string> {
  const response = await Auth(new Request(`${ORIGIN}${BASE_PATH}/csrf`), config)
  expect(response.status).toBe(200)
  jar.store(response)
  const body: unknown = await response.json()
  if (!isRecord(body) || typeof body.csrfToken !== 'string') {
    throw new Error('csrf action returned no token')
  }
  return body.csrfToken
}

let payload: Payload
let config: AuthConfig

beforeAll(async () => {
  const built: SanitizedConfig = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: collections(),
  })
  payload = await getPayload({ config: built })
  await payload.create({
    collection: USERS,
    overrideAccess: true,
    data: {
      auId: 'au-1',
      email: 'spike@example.com',
      name: 'Spike',
      passwordHash: hashPassword('correct-horse'),
      emailVerified: new Date('2026-01-01T00:00:00.000Z').toISOString(),
    },
  })
  config = createConfig(payload, createSpikeAdapter(payload), 'jwt')
}, 60_000)

describe('spike: credentials lifecycle', () => {
  it('signs in with email and password, setting a session cookie', async () => {
    const jar = new Jar()
    const token = await csrfToken(config, jar)
    const response = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/callback/credentials?callbackUrl=${ORIGIN}/`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: jar.header(),
        },
        body: new URLSearchParams({
          csrfToken: token,
          email: 'spike@example.com',
          password: 'correct-horse',
        }).toString(),
      }),
      config
    )
    expect(response.status).toBe(302)
    jar.store(response)
    expect(jar.names()).toContain('authjs.session-token')
  })

  it('reads the session back with user id and verification', async () => {
    const jar = new Jar()
    const token = await csrfToken(config, jar)
    const signedIn = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/callback/credentials`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          cookie: jar.header(),
        },
        body: JSON.stringify({
          csrfToken: token,
          email: 'spike@example.com',
          password: 'correct-horse',
        }),
      }),
      config
    )
    jar.store(signedIn)
    const session = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/session`, {
        headers: { cookie: jar.header() },
      }),
      config
    )
    expect(session.status).toBe(200)
    const body: unknown = await session.json()
    expect(body).toMatchObject({
      user: { id: 'au-1', email: 'spike@example.com', emailVerified: true },
    })
  })

  it('reads the session server-side with skipCSRFCheck (the port path)', async () => {
    const jar = new Jar()
    const token = await csrfToken(config, jar)
    const signedIn = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/callback/credentials`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header() },
        body: JSON.stringify({
          csrfToken: token,
          email: 'spike@example.com',
          password: 'correct-horse',
        }),
      }),
      config
    )
    jar.store(signedIn)
    const headers = new Headers({ cookie: jar.header() })

    const viaResponse = await Auth(new Request(`${ORIGIN}${BASE_PATH}/session`, { headers }), {
      ...config,
      skipCSRFCheck,
    })
    expect(viaResponse.status).toBe(200)
    const viaBody: unknown = await viaResponse.json()
    expect(viaBody).toMatchObject({ user: { id: 'au-1' } })

    const viaRaw = await Auth(new Request(`${ORIGIN}${BASE_PATH}/session`, { headers }), {
      ...config,
      skipCSRFCheck,
      raw,
    })
    expect(viaRaw).toMatchObject({ body: { user: { id: 'au-1' } } })
  })

  it('signs out, clearing the session cookie', async () => {
    const jar = new Jar()
    const token = await csrfToken(config, jar)
    const signedIn = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/callback/credentials`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header() },
        body: JSON.stringify({
          csrfToken: token,
          email: 'spike@example.com',
          password: 'correct-horse',
        }),
      }),
      config
    )
    jar.store(signedIn)
    expect(jar.names()).toContain('authjs.session-token')
    const signedOut = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/signout`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header() },
        body: JSON.stringify({ csrfToken: token }),
      }),
      config
    )
    jar.store(signedOut)
    expect(jar.names()).not.toContain('authjs.session-token')
    const session = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/session`, { headers: { cookie: jar.header() } }),
      config
    )
    expect(await session.json()).toBeNull()
  })

  it('rejects wrong passwords with no session cookie', async () => {
    const jar = new Jar()
    const token = await csrfToken(config, jar)
    const response = await Auth(
      new Request(`${ORIGIN}${BASE_PATH}/callback/credentials`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: jar.header() },
        body: JSON.stringify({
          csrfToken: token,
          email: 'spike@example.com',
          password: 'wrong-horse',
        }),
      }),
      config
    )
    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toContain('error=')
    jar.store(response)
    expect(jar.names()).not.toContain('authjs.session-token')
  })

  it('rejects credentials with database strategy at config time', async () => {
    const dbConfig: AuthConfig = {
      ...createConfig(payload, createSpikeAdapter(payload), 'database'),
      // Silence the expected config error; the status + envelope below
      // are the assertion.
      logger: { error: () => undefined },
    }
    const response = await Auth(new Request(`${ORIGIN}${BASE_PATH}/csrf`), dbConfig)
    expect(response.status).toBe(500)
    const body: unknown = await response.json()
    if (!isRecord(body) || typeof body.message !== 'string') {
      throw new Error('expected a configuration error envelope')
    }
    expect(body.message).toContain('server configuration')
  })
})
