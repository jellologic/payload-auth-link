/**
 * OAuth/OIDC integration (CAP-3, Auth.js): a real Auth.js engine with
 * a standards OIDC provider against a LOCAL mock IdP (in-process HTTP
 * server: discovery, JWKS, authorize, token with a properly signed
 * RS256 `id_token`, userinfo) on real Payload storage. Proves the D6
 * trust split: with `trustProviderEmailVerification: ['mock-oidc']`
 * an IdP asserting `email_verified: true` stamps and links; the same
 * flow asserting `false` links nothing (plugin 401, no user).
 */
import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink, authLinkServer } from '@payload-auth-link/plugin'
import type { AuthConfig } from '@auth/core'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { createAuthJsEngine } from '../engine.js'

const ORIGIN = 'http://oauth-authjs.test'
const SECRET = 'oauth-authjs-integration-secret!!'
const BASE_PATH = '/api/authjs'
const CLIENT_ID = 'mock-client'

type MockProfile = { sub: string; email: string; emailVerified: boolean; name: string }
let nextProfile: MockProfile = {
  sub: 'oidc-1',
  email: 'federated@oauth-authjs.test',
  emailVerified: true,
  name: 'Federated User',
}
const codes = new Map<string, { profile: MockProfile; nonce: string | null }>()

let idp: Server
let idpOrigin = ''
let privateKey: KeyObject
let jwk: Record<string, unknown>

function base64Url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

function signIdToken(profile: MockProfile, nonce: string | null): string {
  const header = base64Url(JSON.stringify({ alg: 'RS256', kid: 'mock-kid', typ: 'JWT' }))
  const now = Math.floor(Date.now() / 1000)
  const payload = base64Url(
    JSON.stringify({
      iss: idpOrigin,
      sub: profile.sub,
      aud: CLIENT_ID,
      exp: now + 600,
      iat: now,
      email: profile.email,
      email_verified: profile.emailVerified,
      name: profile.name,
      ...(nonce === null ? {} : { nonce }),
    })
  )
  const signature = createSign('RSA-SHA256').update(`${header}.${payload}`).sign(privateKey)
  return `${header}.${payload}.${base64Url(signature)}`
}

function startMockIdp(): Promise<void> {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 })
  privateKey = pair.privateKey
  jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'mock-kid', alg: 'RS256', use: 'sig' }
  idp = createServer((request, response) => {
    const url = new URL(request.url ?? '/', idpOrigin || 'http://127.0.0.1')
    const json = (status: number, body: unknown) => {
      response.writeHead(status, { 'content-type': 'application/json' })
      response.end(JSON.stringify(body))
    }
    if (url.pathname === '/.well-known/openid-configuration') {
      json(200, {
        issuer: idpOrigin,
        authorization_endpoint: `${idpOrigin}/authorize`,
        token_endpoint: `${idpOrigin}/token`,
        userinfo_endpoint: `${idpOrigin}/userinfo`,
        jwks_uri: `${idpOrigin}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'email', 'profile'],
        claims_supported: ['sub', 'email', 'email_verified', 'name'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      })
      return
    }
    if (url.pathname === '/jwks') {
      json(200, { keys: [jwk] })
      return
    }
    if (url.pathname === '/authorize') {
      const code = `code-${Math.random().toString(36).slice(2)}`
      codes.set(code, { profile: nextProfile, nonce: url.searchParams.get('nonce') })
      const redirect = new URL(url.searchParams.get('redirect_uri') ?? '/')
      redirect.searchParams.set('code', code)
      const state = url.searchParams.get('state')
      if (state !== null) {
        redirect.searchParams.set('state', state)
      }
      response.writeHead(302, { location: redirect.toString() })
      response.end()
      return
    }
    if (url.pathname === '/token' && request.method === 'POST') {
      let body = ''
      request.on('data', (chunk: Buffer) => {
        body += chunk.toString()
      })
      request.on('end', () => {
        const entry = codes.get(new URLSearchParams(body).get('code') ?? '')
        if (entry === undefined) {
          json(400, { error: 'invalid_grant' })
          return
        }
        json(200, {
          access_token: `at-${entry.profile.sub}`,
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'openid email profile',
          id_token: signIdToken(entry.profile, entry.nonce),
        })
      })
      return
    }
    if (url.pathname === '/userinfo') {
      const token = (request.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
      if (token !== `at-${nextProfile.sub}`) {
        json(401, { error: 'invalid_token' })
        return
      }
      json(200, {
        sub: nextProfile.sub,
        email: nextProfile.email,
        email_verified: nextProfile.emailVerified,
        name: nextProfile.name,
      })
      return
    }
    response.writeHead(404)
    response.end()
  })
  return new Promise((resolve) => {
    idp.listen(0, '127.0.0.1', () => {
      const address = idp.address()
      if (address === null || typeof address === 'string') {
        throw new Error('mock IdP did not bind a port')
      }
      idpOrigin = `http://127.0.0.1:${address.port}`
      resolve()
    })
  })
}

let config: SanitizedConfig
let payload: Payload
let latePayload: Payload | undefined
let engine: ReturnType<typeof createAuthJsEngine>

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
}

beforeAll(async () => {
  await startMockIdp()
  const oidcProvider = (id: string): AuthConfig['providers'][number] => ({
    id,
    name: 'Mock OIDC',
    type: 'oidc',
    issuer: idpOrigin,
    clientId: CLIENT_ID,
    clientSecret: 'mock-secret',
    authorization: { params: { scope: 'openid email profile' } },
  })
  engine = createAuthJsEngine({
    getPayload: () => {
      if (!latePayload) {
        throw new Error('Payload not ready')
      }
      return Promise.resolve(latePayload)
    },
    baseURL: ORIGIN,
    trustProviderEmailVerification: ['mock-oidc'],
    options: {
      basePath: BASE_PATH,
      secret: SECRET,
      // The second provider hits the same IdP but is deliberately NOT
      // on the trust allow-list (CAP-3 proof: non-listed 401s).
      providers: [oidcProvider('mock-oidc'), oidcProvider('untrusted-oidc')],
    },
  })
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
}, 120_000)

afterAll(async () => {
  await new Promise<void>((resolve) => {
    idp.close(() => resolve())
  })
})

async function runFlow(providerId = 'mock-oidc'): Promise<Jar> {
  const jar = new Jar()
  // Auth.js starts OAuth with a CSRF-protected POST to /signin/:id.
  const csrfResponse = await engine.handleRequest(new Request(`${ORIGIN}${BASE_PATH}/csrf`))
  jar.store(csrfResponse)
  const csrfBody = (await csrfResponse.json()) as { csrfToken?: unknown }
  if (typeof csrfBody.csrfToken !== 'string') {
    throw new Error('csrf action returned no token')
  }
  const start = await engine.handleRequest(
    new Request(`${ORIGIN}${BASE_PATH}/signin/${providerId}?callbackUrl=${ORIGIN}/account`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: jar.header(),
      },
      body: new URLSearchParams({ csrfToken: csrfBody.csrfToken }),
      redirect: 'manual',
    })
  )
  jar.store(start)
  const authorizeUrl = start.headers.get('location')
  if (authorizeUrl === null) {
    throw new Error(`signin did not redirect (status ${start.status})`)
  }
  const atIdp = await fetch(authorizeUrl, { redirect: 'manual' })
  const callbackUrl = atIdp.headers.get('location')
  if (callbackUrl === null) {
    throw new Error('mock IdP did not redirect back')
  }
  const callback = new URL(callbackUrl)
  const done = await engine.handleRequest(
    new Request(`${ORIGIN}${callback.pathname}${callback.search}`, {
      headers: { cookie: jar.header() },
      redirect: 'manual',
    })
  )
  jar.store(done)
  const location = done.headers.get('location') ?? ''
  if (location.includes('error=')) {
    throw new Error(`OIDC callback failed: ${location}`)
  }
  return jar
}

function pluginSession(jar: Jar): Promise<Response> {
  return handleEndpoints({
    config,
    request: new Request(`${ORIGIN}/api/auth-link/session`, {
      headers: { cookie: jar.header() },
    }),
  })
}

describe('OIDC with a local mock IdP (CAP-3, Auth.js)', () => {
  it('declares the oauth capability for the configured OIDC provider', () => {
    expect(engine.provider.capabilities.has('oauth')).toBe(true)
  })

  it('stamps, links, and provisions when the IdP asserts email_verified (D6 allow-list)', async () => {
    nextProfile = {
      sub: 'oidc-verified',
      email: 'federated@oauth-authjs.test',
      emailVerified: true,
      name: 'Federated User',
    }
    const jar = await runFlow()
    const portSession = (
      await engine.provider.getSession(new Headers({ cookie: jar.header() }))
    )._unsafeUnwrap()
    expect(portSession?.identity.email).toEqual({
      value: 'federated@oauth-authjs.test',
      verified: true,
    })
    const response = await pluginSession(jar)
    expect(response.status).toBe(200)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'federated@oauth-authjs.test' } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(1)
  })

  it('refuses a verified assertion from a provider NOT on the trust allow-list (D6)', async () => {
    nextProfile = {
      sub: 'oidc-untrusted',
      email: 'untrusted@oauth-authjs.test',
      emailVerified: true,
      name: 'Untrusted Provider User',
    }
    const jar = await runFlow('untrusted-oidc')
    const portSession = (
      await engine.provider.getSession(new Headers({ cookie: jar.header() }))
    )._unsafeUnwrap()
    // The IdP asserted verified, but without the allow-list stamp the
    // adapter user stays unverified and the plugin refuses.
    expect(portSession?.identity.email?.verified).toBe(false)
    const response = await pluginSession(jar)
    expect(response.status).toBe(401)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'untrusted@oauth-authjs.test' } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(0)
  })

  it('refuses (401) and never provisions when email_verified is false', async () => {
    nextProfile = {
      sub: 'oidc-unverified',
      email: 'unverified@oauth-authjs.test',
      emailVerified: false,
      name: 'Unverified User',
    }
    const jar = await runFlow()
    const portSession = (
      await engine.provider.getSession(new Headers({ cookie: jar.header() }))
    )._unsafeUnwrap()
    expect(portSession?.identity.email?.verified).toBe(false)
    const response = await pluginSession(jar)
    expect(response.status).toBe(401)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'unverified@oauth-authjs.test' } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(0)
  })
})

describe('revoke every session of a user on a real Auth.js engine (row 19, issue #86)', () => {
  const profile: MockProfile = {
    sub: 'oidc-revoke-all',
    email: 'revoke-all@oauth-authjs.test',
    emailVerified: true,
    name: 'Revoke All User',
  }

  async function signedInTwice(): Promise<{ jars: [Jar, Jar]; userId: string }> {
    nextProfile = profile
    const first = await runFlow()
    const second = await runFlow()
    expect((await pluginSession(first)).status).toBe(200)
    expect((await pluginSession(second)).status).toBe(200)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: profile.email } },
      overrideAccess: true,
    })
    const user = stored.docs[0]
    if (user === undefined) {
      throw new Error('user was not provisioned')
    }
    return { jars: [first, second], userId: String(user.id) }
  }

  /** How many `aj-sessions` rows the Auth.js store holds for the profile. */
  async function storedSessions(): Promise<number> {
    const users = await payload.find({
      collection: 'aj-users',
      where: { email: { equals: profile.email } },
      limit: 1,
      overrideAccess: true,
    })
    const auId: unknown = users.docs[0]?.auId
    if (typeof auId !== 'string') {
      throw new Error('no Auth.js user for the profile')
    }
    return (
      await payload.count({
        collection: 'aj-sessions',
        where: { userId: { equals: auId } },
        overrideAccess: true,
      })
    ).totalDocs
  }

  it('declares revoke-user-sessions for database sessions', () => {
    expect(engine.provider.capabilities.has('revoke-user-sessions')).toBe(true)
  })

  it('authLinkServer.revokeAllForUser deletes every database session row', async () => {
    const { jars, userId } = await signedInTwice()
    const totalBefore = (await payload.count({ collection: 'aj-sessions', overrideAccess: true }))
      .totalDocs
    const own = await storedSessions()
    expect(own).toBeGreaterThanOrEqual(2)
    await authLinkServer(payload).revokeAllForUser(userId)
    // The store itself: every row of this user gone, nobody else's touched.
    expect(await storedSessions()).toBe(0)
    expect(
      (await payload.count({ collection: 'aj-sessions', overrideAccess: true })).totalDocs
    ).toBe(totalBefore - own)
    for (const jar of jars) {
      expect((await pluginSession(jar)).status).toBe(401)
    }
  })

  it('fails loudly when Payload reports a partially failed bulk delete', async () => {
    const { jars, userId } = await signedInTwice()
    const spy = vi
      .spyOn(payload, 'delete')
      .mockResolvedValueOnce({ docs: [], errors: [{ id: 'x', message: 'locked' }] } as never)
    try {
      await expect(authLinkServer(payload).revokeAllForUser(userId)).rejects.toThrow(
        /revokeAllForUser: authjs: Provider authjs failed during revokeUserSessions/
      )
    } finally {
      spy.mockRestore()
    }
    // Nothing was actually deleted: the rows and sessions are still
    // live, and the operator was told so instead of a false success.
    expect(await storedSessions()).toBeGreaterThanOrEqual(2)
    expect((await pluginSession(jars[0])).status).toBe(200)
    await authLinkServer(payload).revokeAllForUser(userId)
    expect(await storedSessions()).toBe(0)
    expect((await pluginSession(jars[1])).status).toBe(401)
  })

  it('fails loudly when rows survive a delete that reported success', async () => {
    const { userId } = await signedInTwice()
    const spy = vi.spyOn(payload, 'delete').mockResolvedValueOnce({ docs: [], errors: [] })
    try {
      await expect(authLinkServer(payload).revokeAllForUser(userId)).rejects.toThrow(
        /revokeAllForUser: authjs/
      )
    } finally {
      spy.mockRestore()
    }
    expect(await storedSessions()).toBeGreaterThanOrEqual(2)
    await authLinkServer(payload).revokeAllForUser(userId)
    expect(await storedSessions()).toBe(0)
  })
})
