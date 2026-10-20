/**
 * Account-state enforcement at the engine boundary
 * (GHSA-62xf-qq8f-x6w9, GHSA-xxff-hh6q-c99p), on a real Better Auth
 * engine on real Payload storage: an ACTIVE Better Auth admin ban
 * (`banned` + `banExpires`) and the CAP-7 suspension
 * (`suspendedUntil`) each refuse — at the engine's own endpoints
 * (get-session, fresh sign-in) AND through the provider port (session
 * resolution, server-side mints). Before the fix, both states were
 * enforced only where payload-auth-link resolves a session: a banned
 * or suspended user kept working through their existing cookie, and a
 * suspended user could sign in fresh.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { createPayloadRef, PASSWORD } from './engine-harness.js'

const ORIGIN = 'http://account-state.test'
const SECRET = 'account-state-engine-secret-32ch'

const ref = createPayloadRef()
let payload: Payload | undefined

const engine = createBetterAuthEngine({
  getPayload: () => ref.getPayload(),
  // The CAP-7 suspension field on the user row the account-state
  // plugin reads. Declared here so the engine-mode ba-users table
  // carries it.
  customFields: {
    user: [
      { name: 'suspendedUntil', type: 'date' },
      // The admin plugin's ban columns, declared here so the suite can
      // drive bans without installing admin() (whose endpoints ride
      // the role bridging fixed separately).
      { name: 'banned', type: 'boolean' },
      { name: 'banExpires', type: 'date' },
    ],
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    user: {
      additionalFields: {
        suspendedUntil: { type: 'date', input: false },
        banned: { type: 'boolean', defaultValue: false, input: false },
        banExpires: { type: 'date', input: false },
      },
    },
  },
})

function baPost(path: string, body: unknown, cookie?: string): Promise<Response> {
  return engine.auth.handler(
    new Request(`${ORIGIN}/api/auth${path}`, {
      method: 'POST',
      headers: {
        origin: ORIGIN,
        'content-type': 'application/json',
        ...(cookie === undefined ? {} : { cookie }),
      },
      body: JSON.stringify(body),
    })
  )
}

async function baGet(path: string, cookie: string): Promise<Response> {
  return engine.auth.handler(
    new Request(`${ORIGIN}/api/auth${path}`, {
      headers: { origin: ORIGIN, cookie },
    })
  )
}

function sessionCookieOf(response: Response): string {
  const name = engine.sessionCookieNames[0] ?? ''
  const entry = response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith(`${name}=`))
    ?.split(';')[0]
  if (entry === undefined || entry === `${name}=`) {
    throw new Error(`no session cookie set (status ${String(response.status)})`)
  }
  return entry
}

/** The Better Auth user id (`baId`) — what the port's mint takes. */
async function baIdOf(email: string): Promise<string> {
  const found: unknown = await payload?.find({
    collection: 'ba-users',
    where: { email: { equals: email } },
    limit: 1,
    depth: 0,
    overrideAccess: true,
  })
  const doc: unknown = (found as { docs?: unknown[] }).docs?.[0]
  const baId: unknown = (doc as { baId?: unknown } | null)?.baId
  if (typeof baId !== 'string') {
    throw new Error(`no baId for ${email}`)
  }
  return baId
}

beforeAll(async () => {
  const config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    collections: [...engine.collections],
  })
  payload = await getPayload({ config })
  ref.set(payload)
  await engine.auth.$context
}, 120_000)

async function setState(email: string, state: Record<string, unknown>): Promise<void> {
  await payload?.update({
    collection: 'ba-users',
    where: { email: { equals: email } },
    data: state,
    overrideAccess: true,
  })
}

describe('an ACTIVE Better Auth ban refuses the engine boundary (GHSA-62xf)', () => {
  const email = 'banned-live@account-state.test'

  it('a live session stops resolving: get-session 403, port getSession null', async () => {
    const signUp = await baPost('/sign-up/email', {
      name: 'Ban Me',
      email,
      password: PASSWORD,
    })
    expect(signUp.status).toBe(200)
    const cookie = sessionCookieOf(signUp)
    await baGet('/get-session', cookie)
    const before = await engine.provider.getSession(new Headers({ cookie }))
    expect(before.isOk()).toBe(true)
    expect(before.isOk() && before.value !== null).toBe(true)

    await setState(email, { banned: true, banExpires: null })
    const refused = await baGet('/get-session', cookie)
    expect(refused.status).toBe(403)
    const after = await engine.provider.getSession(new Headers({ cookie }))
    if (after.isErr()) {
      console.log('AFTER ERR:', after.error.message)
    }
    expect(after.isOk() && after.value === null).toBe(true)
  })

  it('a fresh sign-in is refused while the ban is active, and works again after it expires', async () => {
    const refused = await baPost('/sign-in/email', { email, password: PASSWORD })
    expect(refused.status).toBe(403)
    await setState(email, { banned: true, banExpires: new Date(Date.now() + 60_000) })
    expect((await baPost('/sign-in/email', { email, password: PASSWORD })).status).toBe(403)
    // The ban expiry passes: the account opens again.
    await setState(email, { banned: true, banExpires: new Date(Date.now() - 1_000) })
    const restored = await baPost('/sign-in/email', { email, password: PASSWORD })
    expect(restored.status).toBe(200)
  })

  it('server-side mints are refused for a banned user', async () => {
    await setState(email, { banned: true, banExpires: null })
    const userId = await baIdOf(email)
    const minted = engine.provider.createProviderSession?.(userId, {
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    if (minted === undefined) {
      throw new Error('the provider cannot mint sessions')
    }
    const result = await minted
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(String(result.error.cause)).toMatch(/ACCOUNT_BANNED/)
    }
  })
})

describe('suspension is enforced at the engine boundary too (GHSA-xxff)', () => {
  const email = 'suspended-live@account-state.test'

  it('a suspended user cannot sign in fresh, and their live session stops resolving', async () => {
    const signUp = await baPost('/sign-up/email', {
      name: 'Suspend Me',
      email,
      password: PASSWORD,
    })
    expect(signUp.status).toBe(200)
    await setState(email, { suspendedUntil: new Date(Date.now() + 3_600_000) })

    const fresh = await baPost('/sign-in/email', { email, password: PASSWORD })
    expect(fresh.status).toBe(403)

    const signedIn = await baPost('/sign-in/email', { email, password: PASSWORD })
    void signedIn
    // The cookie from the sign-up (created BEFORE the suspension) no
    // longer resolves at the engine.
    const cookie = sessionCookieOf(signUp)
    expect((await baGet('/get-session', cookie)).status).toBe(403)
    const viaPort = await engine.provider.getSession(new Headers({ cookie }))
    expect(viaPort.isOk() && viaPort.value === null).toBe(true)
  })

  it('a mint is refused while suspended, and works once the suspension passes', async () => {
    const userId = await baIdOf('suspended-live@account-state.test')
    const mint = engine.provider.createProviderSession?.(userId, {
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    if (mint === undefined) {
      throw new Error('the provider cannot mint sessions')
    }
    expect((await mint).isErr()).toBe(true)
    await setState('suspended-live@account-state.test', {
      suspendedUntil: new Date(Date.now() - 1_000),
    })
    const after = engine.provider.createProviderSession?.(userId, {
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    if (after === undefined) {
      throw new Error('the provider cannot mint sessions')
    }
    expect((await after).isOk()).toBe(true)
  })
})
