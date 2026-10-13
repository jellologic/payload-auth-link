/**
 * Generic OAuth/OIDC integration (CAP-3): a real Better Auth engine
 * with `genericOAuth` against a LOCAL mock identity provider (an
 * in-process HTTP server speaking authorize/token/userinfo) on real
 * Payload storage. Proves the verified-claim gate end to end: an IdP
 * asserting `email_verified: true` links and provisions; the same
 * flow asserting `false` is refused at the plugin (401) and never
 * provisions. No third-party service anywhere.
 */
import { createServer, type Server } from 'node:http'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { authLink } from '@payload-auth-link/plugin'
import { genericOAuth } from 'better-auth/plugins'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://oauth.test'
const SECRET = 'oauth-integration-secret-32-chars!!'

type MockProfile = { sub: string; email: string; emailVerified: boolean; name: string }
let nextProfile: MockProfile = {
  sub: 'idp-1',
  email: 'federated@oauth.test',
  emailVerified: true,
  name: 'Federated User',
}
const codes = new Map<string, MockProfile>()
let idp: Server
let idpOrigin = ''

function startMockIdp(): Promise<void> {
  idp = createServer((request, response) => {
    const url = new URL(request.url ?? '/', idpOrigin || 'http://127.0.0.1')
    if (url.pathname === '/authorize') {
      const code = `code-${Math.random().toString(36).slice(2)}`
      codes.set(code, nextProfile)
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
        const code = new URLSearchParams(body).get('code') ?? ''
        const profile = codes.get(code)
        if (profile === undefined) {
          response.writeHead(400, { 'content-type': 'application/json' })
          response.end(JSON.stringify({ error: 'invalid_grant' }))
          return
        }
        codes.delete(code)
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(
          JSON.stringify({
            access_token: `at-${profile.sub}`,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'openid email profile',
          })
        )
      })
      return
    }
    if (url.pathname === '/userinfo') {
      const token = (request.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
      const profile = token === `at-${nextProfile.sub}` ? nextProfile : undefined
      if (profile === undefined) {
        response.writeHead(401, { 'content-type': 'application/json' })
        response.end(JSON.stringify({ error: 'invalid_token' }))
        return
      }
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(
        JSON.stringify({
          // BA's generic profile mapping reads `id` as the account
          // subject; standards userinfo calls it `sub` — send both.
          id: profile.sub,
          sub: profile.sub,
          email: profile.email,
          email_verified: profile.emailVerified,
          name: profile.name,
        })
      )
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

function makeEngine() {
  return createBetterAuthEngine({
    getPayload: () => {
      if (!latePayload) {
        throw new Error('Payload not ready')
      }
      return Promise.resolve(latePayload)
    },
    options: {
      baseURL: ORIGIN,
      trustedOrigins: [ORIGIN, idpOrigin],
      secret: SECRET,
      emailAndPassword: { enabled: true, requireEmailVerification: false },
      plugins: [
        genericOAuth({
          config: [
            {
              providerId: 'mock-oidc',
              clientId: 'mock-client',
              clientSecret: 'mock-secret',
              authorizationUrl: `${idpOrigin}/authorize`,
              tokenUrl: `${idpOrigin}/token`,
              userInfoUrl: `${idpOrigin}/userinfo`,
              scopes: ['openid', 'email', 'profile'],
            },
          ],
        }),
      ],
    },
  })
}

let engine: ReturnType<typeof makeEngine>

function cookieJar(response: Response, into = new Map<string, string>()): Map<string, string> {
  for (const entry of response.headers.getSetCookie()) {
    const pair = entry.split(';', 1)[0]
    if (pair === undefined || pair === '') {
      continue
    }
    const name = pair.split('=', 1)[0]
    if (name !== undefined && name !== '') {
      into.set(name, pair)
    }
  }
  return into
}

function cookieHeader(jar: Map<string, string>): string {
  return [...jar.values()].join('; ')
}

beforeAll(async () => {
  await startMockIdp()
  engine = makeEngine()
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

afterAll(async () => {
  await new Promise<void>((resolve) => {
    idp.close(() => resolve())
  })
})

async function runOAuthFlow(): Promise<Map<string, string>> {
  const jar = new Map<string, string>()
  // BA starts OAuth via POST /sign-in/social and answers with the
  // provider authorize URL as JSON (the client would navigate there).
  const start = await engine.auth.handler(
    new Request(`${ORIGIN}/api/auth/sign-in/social`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'mock-oidc', callbackURL: '/account' }),
      redirect: 'manual',
    })
  )
  cookieJar(start, jar)
  const startBody = (await start.json().catch(() => null)) as { url?: unknown } | null
  const authorizeUrl =
    typeof startBody?.url === 'string' ? startBody.url : start.headers.get('location')
  if (authorizeUrl === null) {
    throw new Error(`authorize did not redirect (status ${start.status})`)
  }
  const atIdp = await fetch(authorizeUrl, { redirect: 'manual' })
  const callbackUrl = atIdp.headers.get('location')
  if (callbackUrl === null) {
    throw new Error('mock IdP did not redirect back')
  }
  const callback = new URL(callbackUrl)
  const done = await engine.auth.handler(
    new Request(`${ORIGIN}${callback.pathname}${callback.search}`, {
      headers: { origin: ORIGIN, cookie: cookieHeader(jar) },
      redirect: 'manual',
    })
  )
  cookieJar(done, jar)
  return jar
}

describe('generic OAuth with a local mock IdP (CAP-3, Better Auth)', () => {
  it('declares the oauth capability from the installed plugin', () => {
    expect(engine.provider.capabilities.has('oauth')).toBe(true)
  })

  it('links and provisions when the IdP asserts email_verified', async () => {
    nextProfile = {
      sub: 'idp-verified',
      email: 'federated@oauth.test',
      emailVerified: true,
      name: 'Federated User',
    }
    const jar = await runOAuthFlow()
    const cookie = cookieHeader(jar)
    const portSession = (await engine.provider.getSession(new Headers({ cookie })))._unsafeUnwrap()
    expect(portSession?.identity.email).toEqual({
      value: 'federated@oauth.test',
      verified: true,
    })
    const response = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(response.status).toBe(200)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'federated@oauth.test' } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(1)
  })

  it('refuses (401) and never provisions when email_verified is false', async () => {
    nextProfile = {
      sub: 'idp-unverified',
      email: 'unverified@oauth.test',
      emailVerified: false,
      name: 'Unverified User',
    }
    const jar = await runOAuthFlow()
    const cookie = cookieHeader(jar)
    const response = await handleEndpoints({
      config,
      request: new Request(`${ORIGIN}/api/auth-link/session`, { headers: { cookie } }),
    })
    expect(response.status).toBe(401)
    const stored = await payload.find({
      collection: 'users',
      where: { email: { equals: 'unverified@oauth.test' } },
      overrideAccess: true,
    })
    expect(stored.docs).toHaveLength(0)
  })
})
