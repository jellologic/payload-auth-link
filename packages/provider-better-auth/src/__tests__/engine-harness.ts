/**
 * Shared harness for the real-engine credential-path walks (issue #84):
 * a real Better Auth engine on real Payload storage (SQLite in memory)
 * behind a real authLink boot, driven through `engine.auth.handler`
 * and Payload's `handleEndpoints`. One harness — and one Payload
 * instance — per test file (`getPayload` caches per process).
 *
 * The test file builds its own engine (its Better Auth plugins are
 * part of what it pins) around `harness.getPayload`, then calls
 * `harness.boot(config)` in `beforeAll`.
 */
import { handleEndpoints, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { expect } from 'vitest'

export const PASSWORD = 'correct-horse-battery'
export const SUSPENDED_UNTIL = '2031-01-01T00:00:00.000Z'
export const PAST = '2020-01-01T00:00:00.000Z'

/** The engine surface the harness drives. */
export type HarnessEngine = {
  readonly auth: { handler: (request: Request) => Promise<Response> }
  readonly sessionCookieNames: readonly string[]
}

export type Reply = { status: number; body: unknown; headers: Headers }

export type RestOptions = {
  readonly cookie?: string
  readonly body?: unknown
  /** `false` drops the Origin header (no CSRF proof). Default: sent. */
  readonly csrf?: boolean
  readonly authorization?: string
  readonly headers?: Record<string, string>
}

/** Payload ref the engine resolves lazily (it is built before boot). */
export function createPayloadRef(): {
  getPayload: () => Promise<Payload>
  set: (payload: Payload) => void
  live: () => Payload
} {
  let current: Payload | undefined
  const live = (): Payload => {
    if (!current) {
      throw new Error('Payload not ready')
    }
    return current
  }
  return {
    getPayload: () => Promise.resolve(live()),
    set: (payload) => {
      current = payload
    },
    live,
  }
}

export function createHarness(input: {
  origin: string
  engine: HarnessEngine
  ref: ReturnType<typeof createPayloadRef>
}) {
  const { origin, engine, ref } = input
  const { live } = ref
  let config: SanitizedConfig | undefined
  const sessionCookieName = engine.sessionCookieNames[0] ?? ''

  async function boot(built: SanitizedConfig): Promise<Payload> {
    config = built
    const payload = await getPayload({ config: built })
    ref.set(payload)
    return payload
  }

  function liveConfig(): SanitizedConfig {
    if (!config) {
      throw new Error('config not built')
    }
    return config
  }

  function baPost(
    path: string,
    body: unknown,
    opts: { cookie?: string; headers?: Record<string, string> } = {}
  ): Promise<Response> {
    return engine.auth.handler(
      new Request(`${origin}/api/auth${path}`, {
        method: 'POST',
        headers: {
          origin,
          'content-type': 'application/json',
          ...(opts.cookie === undefined ? {} : { cookie: opts.cookie }),
          ...opts.headers,
        },
        body: JSON.stringify(body),
      })
    )
  }

  /** The BA session cookie pair a response set (throws when absent). */
  function sessionCookieOf(response: Response): string {
    const entry = response.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith(`${sessionCookieName}=`))
    if (entry === undefined) {
      throw new Error(`no session cookie set (status ${String(response.status)})`)
    }
    return entry.split(';')[0] ?? ''
  }

  async function signUp(email: string): Promise<string> {
    const response = await baPost('/sign-up/email', { name: 'Paths', email, password: PASSWORD })
    expect(response.status).toBe(200)
    return sessionCookieOf(response)
  }

  async function signIn(email: string, password = PASSWORD): Promise<string> {
    const response = await baPost('/sign-in/email', { email, password })
    expect(response.status).toBe(200)
    return sessionCookieOf(response)
  }

  /** Mark the BA user verified (or not) in the provider's own store. */
  async function markBaVerified(email: string, verified = true): Promise<void> {
    await live().update({
      collection: 'ba-users',
      where: { email: { equals: email } },
      data: { emailVerified: verified },
      overrideAccess: true,
    })
  }

  /** BA's own user id (`baId`), which its session rows reference. */
  async function baUserId(email: string): Promise<string> {
    const found = await live().find({
      collection: 'ba-users',
      where: { email: { equals: email } },
      limit: 1,
      overrideAccess: true,
    })
    const id: unknown = found.docs[0]?.baId
    if (typeof id !== 'string') {
      throw new Error(`no BA user ${email}`)
    }
    return id
  }

  /** The raw session token inside a signed BA session cookie pair. */
  function rawTokenOf(cookie: string): string {
    const value = decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1))
    return value.split('.')[0] ?? ''
  }

  /** The signed token value of a BA session cookie pair (URL-decoded). */
  function signedTokenOf(cookie: string): string {
    return decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1))
  }

  /** A signed-up, BA-verified, signed-in user's session cookie. */
  async function verifiedSession(email: string): Promise<string> {
    await signUp(email)
    await markBaVerified(email)
    return signIn(email)
  }

  async function rest(method: string, path: string, opts: RestOptions = {}): Promise<Reply> {
    const headers: Record<string, string> = { ...opts.headers }
    if (opts.csrf !== false) {
      headers.origin = origin
    }
    if (opts.cookie !== undefined) {
      headers.cookie = opts.cookie
    }
    if (opts.authorization !== undefined) {
      headers.authorization = opts.authorization
    }
    if (opts.body !== undefined) {
      headers['content-type'] = 'application/json'
    }
    const response = await handleEndpoints({
      config: liveConfig(),
      request: new Request(`${origin}/api${path}`, {
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

  function pluginSession(cookie: string): Promise<Reply> {
    return rest('GET', '/auth-link/session', { cookie })
  }

  /** The host user id a reply's `user` carries (throws when absent). */
  function userIdOf(reply: Reply): string {
    const id = (reply.body as { user?: { id?: unknown } | null } | null)?.user?.id
    if (typeof id !== 'string' && typeof id !== 'number') {
      throw new Error(`the bridge resolved no user (status ${String(reply.status)})`)
    }
    return String(id)
  }

  /** The host user id the bridge resolved for a cookie (asserts 200). */
  async function hostIdOf(cookie: string): Promise<string> {
    const reply = await pluginSession(cookie)
    expect(reply.status).toBe(200)
    return userIdOf(reply)
  }

  async function hostDoc(id: string | number): Promise<Record<string, unknown>> {
    return live().findByID({
      collection: 'users',
      id,
      depth: 0,
      overrideAccess: true,
      showHiddenFields: true,
    })
  }

  async function hostDocByEmail(email: string): Promise<Record<string, unknown> | undefined> {
    const found = await live().find({
      collection: 'users',
      where: { email: { equals: email } },
      limit: 1,
      depth: 0,
      overrideAccess: true,
      showHiddenFields: true,
    })
    return found.docs[0]
  }

  function identitiesOf(doc: Record<string, unknown> | undefined): unknown[] {
    const identities = doc?.identities
    return Array.isArray(identities) ? identities : []
  }

  /** A host document created outside the plugin (Local API, no marker). */
  async function createDoc(email: string, data: Record<string, unknown> = {}): Promise<string> {
    const created = await live().create({
      collection: 'users',
      data: { email, password: PASSWORD, roles: ['user'], ...data },
      overrideAccess: true,
      disableVerificationEmail: true,
    })
    return String(created.id)
  }

  /** The role manager's proof grant (the runbook's manager action). */
  async function grantProof(id: string, email: string): Promise<void> {
    await live().update({
      collection: 'users',
      id,
      data: { linkable: true, linkableEmail: email },
      overrideAccess: true,
    })
  }

  async function suspend(id: string, until: string | null = SUSPENDED_UNTIL): Promise<void> {
    await live().update({
      collection: 'users',
      id,
      data: { suspendedUntil: until },
      overrideAccess: true,
    })
  }

  /** A proven host document linked through a real BA sign-in. */
  async function linkedUser(
    email: string,
    data: Record<string, unknown> = {}
  ): Promise<{ id: string; cookie: string }> {
    const id = await createDoc(email, { linkable: true, linkableEmail: email, ...data })
    const cookie = await verifiedSession(email)
    expect(await hostIdOf(cookie)).toBe(id)
    return { id, cookie }
  }

  function localLogin(email: string, password = PASSWORD): Promise<Reply> {
    return rest('POST', '/users/login', { body: { email, password } })
  }

  function jwtCookieOf(reply: Reply): string {
    const cookie = (reply.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
    expect(cookie).toMatch(/^payload-token=./)
    return cookie
  }

  async function accessOf(opts: RestOptions): Promise<{ canAccessAdmin: unknown }> {
    const access = await rest('GET', '/access', opts)
    expect(access.status).toBe(200)
    return { canAccessAdmin: (access.body as { canAccessAdmin?: unknown }).canAccessAdmin }
  }

  async function meId(opts: RestOptions): Promise<string | null> {
    const me = await rest('GET', '/users/me', opts)
    const user = (me.body as { user?: { id?: unknown } | null } | null)?.user
    return user === null || user === undefined ? null : String(user.id)
  }

  /** Whether a credential can read a users document over REST. */
  async function readsDoc(opts: RestOptions, id: string): Promise<boolean> {
    const read = await rest('GET', `/users/${id}`, opts)
    return read.status === 200 && String((read.body as { id?: unknown }).id) === id
  }

  return {
    sessionCookieName,
    boot,
    config: liveConfig,
    live,
    baPost,
    sessionCookieOf,
    signUp,
    signIn,
    markBaVerified,
    baUserId,
    rawTokenOf,
    signedTokenOf,
    verifiedSession,
    rest,
    pluginSession,
    userIdOf,
    hostIdOf,
    hostDoc,
    hostDocByEmail,
    identitiesOf,
    createDoc,
    grantProof,
    suspend,
    linkedUser,
    localLogin,
    jwtCookieOf,
    accessOf,
    meId,
    readsDoc,
  }
}
