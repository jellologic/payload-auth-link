/**
 * The Auth.js session JSON (`GET {basePath}/session`) on a REAL engine:
 * real `@auth/core` 0.41 with a magic-link provider on real Payload
 * storage (SQLite in memory), for both session strategies, with and
 * without a builder `session` callback. Sessions are minted by Auth.js's
 * own sign-in and callback actions.
 *
 * The response is the allowlisted shape — `user` (name / email / image
 * plus the port's `id` and `emailVerified`) and `expires` — and carries
 * no credential: no `sessionToken` / `userId` key at any depth, and no
 * value equal to any cookie the sign-in set. A builder callback that
 * spreads the session it is given keeps its own keys and loses only the
 * adapter session row fields; one that NESTS the session (or copies the
 * token under another key) loses the credential at every depth.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { AuthConfig } from '@auth/core'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAuthJsEngine, type AuthJsEngine } from '../engine.js'

const ORIGIN = 'http://session-shape-authjs.test'
const SECRET = 'session-shape-authjs-engine-secret!!!!'
const BASE_PATH = '/api/authjs'

/** Outbox: the last magic-link URL Auth.js sent per address. */
const outbox = new Map<string, string>()

const magicLink: AuthConfig['providers'][number] = {
  id: 'magic',
  type: 'email',
  name: 'Magic link',
  maxAge: 600,
  sendVerificationRequest: ({ identifier, url }) => {
    outbox.set(identifier, url)
  },
}

let payload: Payload | undefined

type Strategy = 'jwt' | 'database'
type Builder = 'none' | 'spread' | 'nest'

/** A builder callback that hands back everything it was given, plus a key. */
const spreadingSession: NonNullable<NonNullable<AuthConfig['callbacks']>['session']> = ({
  session,
}) => {
  const extended = { ...session, theme: 'dark' }
  return extended
}

/**
 * A careless builder callback: it nests the whole session (database
 * strategy: the adapter row, `sessionToken` included) and copies the
 * token into an array and a derived string under unrelated keys.
 */
const nestingSession: NonNullable<NonNullable<AuthConfig['callbacks']>['session']> = ({
  session,
}) => {
  const token: unknown = (session as { sessionToken?: unknown }).sessionToken
  const raw = typeof token === 'string' ? token : 'no-token'
  const extended = {
    ...session,
    theme: 'dark',
    debug: { s: session, depth: { again: [session, raw] } },
    trace: [raw, 'kept'],
    header: `Bearer ${raw}`,
  }
  return extended
}

const builders = { spread: spreadingSession, nest: nestingSession } as const

function engineFor(strategy: Strategy, builder: Builder): AuthJsEngine {
  return createAuthJsEngine({
    getPayload: () => {
      if (!payload) {
        throw new Error('Payload not ready')
      }
      return Promise.resolve(payload)
    },
    baseURL: ORIGIN,
    options: {
      basePath: BASE_PATH,
      secret: SECRET,
      session: { strategy },
      providers: [magicLink],
      ...(builder === 'none' ? {} : { callbacks: { session: builders[builder] } }),
    },
  })
}

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

  get(name: string): string | undefined {
    return this.pairs.get(name)
  }

  values(): string[] {
    return [...this.pairs.values()]
  }

  header(): string {
    return [...this.pairs.entries()].map(([name, value]) => `${name}=${value}`).join('; ')
  }
}

/** A full Auth.js magic-link sign-in; returns the jar holding its cookies. */
async function signIn(engine: AuthJsEngine, email: string): Promise<Jar> {
  const jar = new Jar()
  outbox.delete(email)
  const csrf = await engine.handleRequest(new Request(`${ORIGIN}${BASE_PATH}/csrf`))
  jar.store(csrf)
  const { csrfToken } = (await csrf.json()) as { csrfToken?: unknown }
  if (typeof csrfToken !== 'string') {
    throw new Error('csrf action returned no token')
  }
  jar.store(
    await engine.handleRequest(
      new Request(`${ORIGIN}${BASE_PATH}/signin/magic`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
        body: new URLSearchParams({ csrfToken, email, callbackUrl: `${ORIGIN}/account` }),
        redirect: 'manual',
      })
    )
  )
  const url = outbox.get(email)
  if (url === undefined) {
    throw new Error('no magic link sent')
  }
  const target = new URL(url)
  const done = await engine.handleRequest(
    new Request(`${ORIGIN}${target.pathname}${target.search}`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    })
  )
  jar.store(done)
  expect(done.headers.get('location') ?? '').not.toContain('error=')
  return jar
}

/** Every key and every string value of a JSON document, at any depth. */
function walk(value: unknown, keys: string[] = [], strings: string[] = []) {
  if (typeof value === 'string') {
    strings.push(value)
  } else if (Array.isArray(value)) {
    for (const item of value) {
      walk(item, keys, strings)
    }
  } else if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      keys.push(key)
      walk(item, keys, strings)
    }
  }
  return { keys, strings }
}

const cases = [
  { strategy: 'jwt', builder: 'none' },
  { strategy: 'jwt', builder: 'spread' },
  { strategy: 'jwt', builder: 'nest' },
  { strategy: 'database', builder: 'none' },
  { strategy: 'database', builder: 'spread' },
  { strategy: 'database', builder: 'nest' },
] as const

const engines = cases.map((c) => ({ ...c, engine: engineFor(c.strategy, c.builder) }))

beforeAll(async () => {
  const first = engines[0]
  if (first === undefined) {
    throw new Error('no engine')
  }
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: [{ slug: 'users', auth: true, fields: [] }, ...first.engine.collections],
  })
  payload = await getPayload({ config })
}, 120_000)

describe('Auth.js session JSON (real engine)', () => {
  it.each(engines)(
    '$strategy strategy, builder session callback: $builder — carries no credential',
    async ({ strategy, builder, engine }) => {
      const email = `${strategy}-${builder}@session-shape.test`
      const jar = await signIn(engine, email)
      const sessionCookie = jar.get(engine.sessionCookieNames[0] ?? '')
      expect(sessionCookie).toBeDefined()

      const response = await engine.handleRequest(
        new Request(`${ORIGIN}${BASE_PATH}/session`, { headers: { cookie: jar.header() } })
      )
      expect(response.status).toBe(200)
      const body = (await response.json()) as Record<string, unknown>

      const { keys, strings } = walk(body)
      expect(keys).not.toContain('sessionToken')
      if (builder !== 'nest') {
        expect(keys).not.toContain('userId')
      }
      const cookieValues = jar.values()
      expect(cookieValues.length).toBeGreaterThan(0)
      for (const value of cookieValues) {
        for (const string of strings) {
          expect(string).not.toContain(value)
          expect(string).not.toContain(decodeURIComponent(value))
        }
      }

      const user = body.user as Record<string, unknown> | undefined
      expect(user?.email).toBe(email)
      expect(typeof user?.id).toBe('string')
      expect(user?.emailVerified).toBe(true)
      expect(typeof body.expires).toBe('string')
      if (builder === 'spread') {
        expect(body.theme).toBe('dark')
        expect(Object.keys(body).sort()).toEqual(['expires', 'theme', 'user'])
      } else if (builder === 'nest') {
        // Only the credential goes: the builder's own keys and the
        // nested session data stay.
        expect(body.theme).toBe('dark')
        const nested = (body.debug as { s?: { user?: { email?: unknown } } } | undefined)?.s
        expect(nested?.user?.email).toBe(email)
        if (strategy === 'database') {
          // The token-bearing array item and string are gone.
          expect(body.trace).toEqual(['kept'])
          expect(Object.keys(body).sort()).toEqual(['debug', 'expires', 'theme', 'trace', 'user'])
        } else {
          // JWT sessions hand the callback no database token.
          expect(body.trace).toEqual(['no-token', 'kept'])
          expect(body.header).toBe('Bearer no-token')
        }
      } else {
        expect(Object.keys(body).sort()).toEqual(['expires', 'user'])
        expect(Object.keys(user ?? {}).sort()).toEqual(['email', 'emailVerified', 'id'])
      }
    }
  )
})
