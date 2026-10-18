/**
 * Credential-path matrix row 28 on Better Auth (issue #113): BA's own
 * session JSON — `/get-session`, `/list-sessions` and the sign-in /
 * sign-up bodies — never hands page JavaScript a raw session token by
 * default. With BA's `bearer()` plugin installed (without
 * `requireSignature`), that raw token IS a working
 * `Authorization: Bearer` credential, pinned below on an engine that
 * opts back in (`exposeSessionTokens: true`).
 *
 * Real BA 1.7 on real Payload storage (SQLite in memory) behind a real
 * authLink boot. Two engines share the one Payload instance under
 * different slugs; only the default one is registered with the plugin.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { nullLogger, type LoggerPort } from '@payload-auth-link/core'
import { bearer } from 'better-auth/plugins'
import { buildConfig } from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { createHarness, createPayloadRef, PASSWORD } from './engine-harness.js'

const ORIGIN = 'http://session-json-ba.test'
const SECRET = 'session-json-ba-engine-secret!!!!!!'

const baseOptions = {
  baseURL: ORIGIN,
  trustedOrigins: [ORIGIN],
  secret: SECRET,
  rateLimit: { enabled: false },
  emailAndPassword: { enabled: true, requireEmailVerification: false },
  plugins: [bearer()],
}

const ref = createPayloadRef()
const engine = createBetterAuthEngine({ getPayload: ref.getPayload, options: baseOptions })
const h = createHarness({ origin: ORIGIN, engine, ref })

const exposedWarn = vi.fn()
const exposedLogger: LoggerPort = { ...nullLogger(), warn: exposedWarn }
const exposed = createBetterAuthEngine({
  getPayload: ref.getPayload,
  slugs: {
    user: 'ba2-users',
    session: 'ba2-sessions',
    account: 'ba2-accounts',
    verification: 'ba2-verifications',
    rateLimit: 'ba2-rate-limits',
  },
  exposeSessionTokens: true,
  logger: exposedLogger,
  options: baseOptions,
})
const x = createHarness({ origin: ORIGIN, engine: exposed, ref })

beforeAll(async () => {
  await h.boot(
    await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      collections: [
        { slug: 'users', auth: true, fields: [] },
        ...engine.collections,
        ...exposed.collections,
      ],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          providers: [engine.provider],
        }),
      ],
    })
  )
  await engine.auth.$context
  await exposed.auth.$context
}, 120_000)

function baGet(
  target: typeof engine,
  path: string,
  headers: Record<string, string>
): Promise<Response> {
  return target.auth.handler(
    new Request(`${ORIGIN}/api/auth${path}`, { headers: { origin: ORIGIN, ...headers } })
  )
}

async function json(response: Response): Promise<{ text: string; body: unknown }> {
  const text = await response.text()
  return { text, body: JSON.parse(text) as unknown }
}

describe('row 28: Better Auth session JSON carries no session token (default)', () => {
  it('sign-up and sign-in bodies omit the minted token; the cookie still works', async () => {
    const email = 'json-signin@ba-json.test'
    const signUp = await h.baPost('/sign-up/email', { name: 'J', email, password: PASSWORD })
    expect(signUp.status).toBe(200)
    const up = await json(signUp)
    expect(up.body).toMatchObject({ user: { email } })
    expect(up.body).not.toHaveProperty('token')
    expect(up.text).not.toContain(h.rawTokenOf(h.sessionCookieOf(signUp)))

    await h.markBaVerified(email)
    const signIn = await h.baPost('/sign-in/email', { email, password: PASSWORD })
    expect(signIn.status).toBe(200)
    const cookie = h.sessionCookieOf(signIn)
    const inBody = await json(signIn)
    expect(inBody.body).toMatchObject({ user: { email } })
    expect(inBody.body).not.toHaveProperty('token')
    expect(inBody.text).not.toContain(h.rawTokenOf(cookie))
    // The HttpOnly cookie is the credential; the bridge resolves it.
    expect((await h.pluginSession(cookie)).status).toBe(200)
  })

  it('/get-session answers the session without its token; server-side api keeps it', async () => {
    const email = 'json-get@ba-json.test'
    const cookie = await h.verifiedSession(email)
    const raw = h.rawTokenOf(cookie)
    const response = await baGet(engine, '/get-session', { cookie })
    expect(response.status).toBe(200)
    const { text, body } = await json(response)
    expect(body).toMatchObject({ user: { email } })
    const session = (body as { session: Record<string, unknown> }).session
    expect(session.id).toEqual(expect.any(String))
    expect(session).not.toHaveProperty('token')
    expect(text).not.toContain(raw)
    // Trusted server code (and the port) still reads the full row.
    const server = (await engine.auth.api.getSession({
      headers: new Headers({ cookie }),
    })) as { session?: { token?: unknown } } | null
    expect(server?.session?.token).toBe(raw)
  })

  it('/list-sessions lists every session by id, never by token', async () => {
    const email = 'json-list@ba-json.test'
    const first = await h.verifiedSession(email)
    const second = await h.signIn(email)
    const response = await baGet(engine, '/list-sessions', { cookie: second })
    expect(response.status).toBe(200)
    const { text, body } = await json(response)
    const entries = body as Record<string, unknown>[]
    // The sign-up session plus two sign-ins.
    expect(entries).toHaveLength(3)
    for (const entry of entries) {
      expect(entry).not.toHaveProperty('token')
      expect(entry.id).toEqual(expect.any(String))
    }
    expect(text).not.toContain(h.rawTokenOf(first))
    expect(text).not.toContain(h.rawTokenOf(second))
  })

  it('/revoke-session takes a listed id (own sessions only); a raw token still works', async () => {
    const email = 'json-revoke@ba-json.test'
    const doomed = await h.verifiedSession(email)
    const keeper = await h.signIn(email)
    const other = await h.verifiedSession('json-revoke-other@ba-json.test')
    const ids = async (cookie: string): Promise<string[]> =>
      ((await (await baGet(engine, '/list-sessions', { cookie })).json()) as { id: string }[]).map(
        (entry) => entry.id
      )
    const doomedId = (
      (await (await baGet(engine, '/get-session', { cookie: doomed })).json()) as {
        session: { id: string }
      }
    ).session.id
    expect(await ids(keeper)).toContain(doomedId)

    // Another user's session id revokes nothing.
    const [otherId] = await ids(other)
    expect(otherId).toEqual(expect.any(String))
    const foreign = await h.baPost('/revoke-session', { token: otherId }, { cookie: keeper })
    expect(foreign.status).toBe(200)
    expect((await h.pluginSession(other)).status).toBe(200)

    const revoked = await h.baPost('/revoke-session', { token: doomedId }, { cookie: keeper })
    expect(revoked.status).toBe(200)
    expect((await h.pluginSession(doomed)).status).toBe(401)
    expect((await h.pluginSession(keeper)).status).toBe(200)
    expect(await ids(keeper)).not.toContain(doomedId)

    // BA's documented call shape (a raw token) is unchanged.
    const third = await h.signIn(email)
    const byToken = await h.baPost(
      '/revoke-session',
      { token: h.rawTokenOf(third) },
      { cookie: keeper }
    )
    expect(byToken.status).toBe(200)
    expect((await h.pluginSession(third)).status).toBe(401)
  })
})

describe('row 28 opt-out: exposeSessionTokens: true (why the default redacts)', () => {
  it('logs the bearer() exposure warning at wiring time', () => {
    expect(exposedWarn).toHaveBeenCalledWith(
      expect.stringContaining('bearer() is installed without requireSignature'),
      expect.objectContaining({ setting: 'bearer' })
    )
  })

  it('a token read from the JSON is a working Bearer credential', async () => {
    const email = 'json-exposed@ba-json.test'
    await x.signUp(email)
    await x.markBaVerified(email)
    const signIn = await x.baPost('/sign-in/email', { email, password: PASSWORD })
    expect(signIn.status).toBe(200)
    const raw = x.rawTokenOf(x.sessionCookieOf(signIn))
    expect(((await signIn.json()) as { token?: unknown }).token).toBe(raw)
    const cookie = x.sessionCookieOf(signIn)
    const session = (await (await baGet(exposed, '/get-session', { cookie })).json()) as {
      session: { token?: unknown }
    }
    expect(session.session.token).toBe(raw)
    const listed = (await (await baGet(exposed, '/list-sessions', { cookie })).json()) as {
      token?: unknown
    }[]
    expect(listed.map((entry) => entry.token)).toContain(raw)
    // Script that read the JSON now authenticates without the cookie.
    const asBearer = await baGet(exposed, '/get-session', { authorization: `Bearer ${raw}` })
    expect(asBearer.status).toBe(200)
    expect(await asBearer.json()).toMatchObject({ user: { email } })
  })
})
