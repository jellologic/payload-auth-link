/**
 * JIT-link proof vs. Payload's own `_verified` flag, on a real engine
 * (Payload on SQLite in memory) with a host users collection using
 * `auth: { verify: true }` and open self-registration.
 *
 * The chain this file pins (each step fails without its fix):
 * 1. A self-registered, Payload-verified, unlinked document whose
 *    owner changes its email to someone else's address loses every
 *    proof (`linkable`, `linkableEmail`, `_verified`) with the change.
 * 2. The provider sign-up of the real owner of that address is
 *    refused (typed 401, logged) — never linked to the squatting
 *    document, never a raw storage error.
 * 3. `_verified` alone never admits a document to email linking.
 * 4. A local session issued BEFORE a legitimate link is dead after it
 *    (Payload `useSessions`: the sessions array is cleared on link).
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { LogFields, LoggerPort } from '@payload-auth-link/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://verified-linking.test'
const SECRET = 'verified-linking-secret-32-chars!'

type LogCall = { readonly message: string; readonly fields: LogFields | undefined }
const warnCalls: LogCall[] = []
const infoCalls: LogCall[] = []
const errorCalls: LogCall[] = []
const capturingLogger: LoggerPort = {
  debug: () => undefined,
  info: (message, fields) => {
    infoCalls.push({ message, fields })
  },
  warn: (message, fields) => {
    warnCalls.push({ message, fields })
  },
  error: (message, fields) => {
    errorCalls.push({ message, fields })
  },
  child: () => capturingLogger,
}

let config: SanitizedConfig
let payload: Payload
const stub = createStubProvider()

type Reply = { status: number; body: unknown; headers: Headers }

async function rest(
  method: string,
  path: string,
  opts: { cookie?: string; body?: unknown } = {}
): Promise<Reply> {
  const headers: Record<string, string> = {
    origin: ORIGIN,
    'x-auth-link-csrf': '1',
  }
  if (opts.cookie !== undefined) {
    headers.cookie = opts.cookie
  }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
  }
  const response = await handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    }),
  })
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  return { status: response.status, body, headers: response.headers }
}

function tokenCookie(reply: Reply): string {
  const cookie = (reply.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
  expect(cookie).toMatch(/^payload-token=./)
  return cookie
}

async function rawDoc(id: string | number): Promise<Record<string, unknown>> {
  const doc = await payload.findByID({
    collection: 'users',
    id,
    depth: 0,
    overrideAccess: true,
    showHiddenFields: true,
  })
  return doc
}

/** `/users/me` as the holder of `cookie` sees it (null when the JWT is dead). */
async function meId(cookie: string): Promise<string | null> {
  const me = await rest('GET', '/users/me', { cookie })
  const user = (me.body as { user?: { id?: unknown } | null } | null)?.user
  return user === null || user === undefined ? null : String(user.id)
}

beforeAll(async () => {
  config = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    collections: [
      {
        slug: 'users',
        // Host-managed local accounts with Payload email verification
        // and open self-registration: the shape where `_verified`
        // exists and a stranger can hold a verified document.
        auth: { verify: true },
        access: { create: () => true },
        fields: [],
      },
    ],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['admin', 'user'],
        defaultRole: 'user',
        providers: [stub.provider],
        logger: capturingLogger,
      }),
    ],
  })
  payload = await getPayload({ config })
}, 60_000)

describe('a verified, unlinked document cannot squat on another email', () => {
  const attacker = 'attacker@verified.test'
  const victim = 'victim@verified.test'
  const password = 'attacker-password-1'
  let attackerId: string | number = ''

  it('self-registration, Payload verification, and local sign-in work as the host intends', async () => {
    const registered = await rest('POST', '/users', { body: { email: attacker, password } })
    expect(registered.status).toBe(201)
    attackerId = (registered.body as { doc: { id: string | number } }).doc.id
    const before = await rawDoc(attackerId)
    // Self-registered: never proven by the plugin.
    expect(before.linkable).toBe(false)
    const token = before._verificationToken
    expect(typeof token).toBe('string')
    const verified = await rest('POST', `/users/verify/${String(token)}`)
    expect(verified.status).toBe(200)
    expect((await rawDoc(attackerId))._verified).toBe(true)
  })

  it('an email change outside the provider resync resets every proof', async () => {
    const login = await rest('POST', '/users/login', { body: { email: attacker, password } })
    expect(login.status).toBe(200)
    const jwt = tokenCookie(login)
    const moved = await rest('PATCH', `/users/${String(attackerId)}`, {
      cookie: jwt,
      body: { email: victim },
    })
    expect(moved.status).toBe(200)
    const after = await rawDoc(attackerId)
    expect(after.email).toBe(victim)
    expect(after.linkable).toBe(false)
    expect(after.linkableEmail ?? null).toBeNull()
    // Payload keeps `_verified` across email changes on its own; the
    // plugin resets it so the new address must be re-verified.
    expect(after._verified).toBe(false)
  })

  it("the address owner's provider sign-up is refused, typed and logged, never linked", async () => {
    warnCalls.length = 0
    errorCalls.length = 0
    const session = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-victim',
        providerUserId: 'stub-victim',
        email: victim,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(session.status).toBe(401)
    const squatted = await rawDoc(attackerId)
    expect(squatted.identities).toEqual([])
    expect(
      warnCalls.some((call) => call.message.includes('not marked linkable') && call.fields)
    ).toBe(true)
    expect(warnCalls.some((call) => call.message.startsWith('provisioning refused'))).toBe(true)
    // A refusal, not a storage outage.
    expect(errorCalls).toEqual([])
  })

  it('`_verified` alone never admits a document to email linking', async () => {
    // Even with Payload's flag restored (any signed-in user can write
    // `_verified` under Payload's default field access), the
    // document never proved it owns the address.
    await payload.update({
      collection: 'users',
      id: attackerId,
      data: { _verified: true },
      overrideAccess: true,
    })
    const session = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-victim-2',
        providerUserId: 'stub-victim',
        email: victim,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(session.status).toBe(401)
    expect((await rawDoc(attackerId)).identities).toEqual([])
  })
})

describe('local sessions issued before linking', () => {
  const owner = 'owner@verified.test'
  const password = 'owner-password-1'
  let ownerId: string | number = ''

  beforeAll(async () => {
    // A proven, verified host account (the runbook shape for a
    // pre-existing user a role manager vouched for).
    const created = await payload.create({
      collection: 'users',
      data: {
        email: owner,
        password,
        roles: ['user'],
        linkable: true,
        linkableEmail: owner,
        _verified: true,
      },
      overrideAccess: true,
    })
    ownerId = created.id
  })

  it('a pre-link local JWT is refused after the provider link', async () => {
    const login = await rest('POST', '/users/login', { body: { email: owner, password } })
    expect(login.status).toBe(200)
    const jwt = tokenCookie(login)
    expect(await meId(jwt)).toBe(String(ownerId))

    const linked = await rest('GET', '/auth-link/session', {
      cookie: stub.issue({
        sessionId: 'sess-owner',
        providerUserId: 'stub-owner',
        email: owner,
        expiresAt: new Date(Date.now() + 3600_000),
      }),
    })
    expect(linked.status).toBe(200)
    const doc = await rawDoc(ownerId)
    expect(doc.identities).toEqual([expect.objectContaining({ providerUserId: 'stub-owner' })])
    expect(doc.sessions).toEqual([])
    expect(
      infoCalls.some((call) => call.message === 'local sessions revoked on identity link')
    ).toBe(true)

    // The JWT minted before the link no longer authenticates.
    expect(await meId(jwt)).toBeNull()
    const write = await rest('PATCH', `/users/${String(ownerId)}`, {
      cookie: jwt,
      body: { email: 'elsewhere@verified.test' },
    })
    expect(write.status).not.toBe(200)
    expect((await rawDoc(ownerId)).email).toBe(owner)
  })
})
