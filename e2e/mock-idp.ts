/**
 * Local mock identity provider for the external-IdP e2e variant
 * (`playwright.idp.config.ts`, `playwright.tanstack-idp.config.ts`).
 * Started by Playwright as a `webServer` (`bun mock-idp.ts`); it
 * imports node builtins only, so it runs from a fresh clone without
 * workspace resolution.
 *
 * It speaks just enough OpenID Connect for Better Auth's
 * `genericOAuth` and an Auth.js `oidc` provider: discovery, JWKS, an
 * authorize page (a real HTML form the spec fills — the "consent
 * screen"), a token endpoint returning an RS256 `id_token`, and
 * userinfo. It also mints Google-shaped One Tap ID tokens
 * (`iss: https://accounts.google.com`) signed by its own key and
 * serves that key as a JWKS — the endpoint the Auth.js One Tap recipe
 * is pointed at (`jwksUrl`) in the variant. Better Auth's `oneTap`
 * verifies against Google's hardcoded JWKS instead, so for it these
 * tokens are forgeries by construction.
 *
 * Deliberately permissive where a mock may be: any `client_id` is
 * accepted (the token's `aud` echoes it), the client secret and PKCE
 * verifier are not checked. Codes are single-use and kept in memory.
 * Never deploy this.
 */
import { createSign, generateKeyPairSync, randomBytes } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'

const port = Number(process.env.MOCK_IDP_PORT ?? '3190')
const origin = `http://localhost:${String(port)}`
const googleIssuer = 'https://accounts.google.com'

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const kid = 'mock-idp-key-1'
const jwks = {
  keys: [{ ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' }],
}

type Profile = { sub: string; email: string; emailVerified: boolean; name: string }
type Grant = { profile: Profile; clientId: string; nonce: string | null }

const codes = new Map<string, Grant>()
const accessTokens = new Map<string, Profile>()

function base64Url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

function signJwt(claims: Record<string, unknown>): string {
  const header = base64Url(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }))
  const body = base64Url(JSON.stringify(claims))
  const signature = createSign('RSA-SHA256').update(`${header}.${body}`).sign(privateKey)
  return `${header}.${body}.${base64Url(signature)}`
}

/** Stable subject per email, so a repeat sign-in is the same account. */
function subjectFor(email: string): string {
  return `mock-${Buffer.from(email.toLowerCase()).toString('hex').slice(0, 40)}`
}

function idTokenClaims(
  profile: Profile,
  audience: string,
  issuer: string
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: issuer,
    sub: profile.sub,
    aud: audience,
    iat: now,
    exp: now + 600,
    email: profile.email,
    email_verified: profile.emailVerified,
    name: profile.name,
  }
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  response.end(JSON.stringify(body))
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = ''
    request.on('data', (chunk: Buffer) => {
      body += chunk.toString()
    })
    request.on('end', () => resolve(body))
    request.on('error', reject)
  })
}

function parseBody(request: IncomingMessage, raw: string): URLSearchParams {
  if ((request.headers['content-type'] ?? '').includes('application/json')) {
    const parsed = JSON.parse(raw === '' ? '{}' : raw) as Record<string, unknown>
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(parsed)) {
      params.set(key, String(value))
    }
    return params
  }
  return new URLSearchParams(raw)
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

/** The "consent screen": the spec types who signs in. */
function authorizePage(query: URLSearchParams): string {
  const hidden = ['client_id', 'redirect_uri', 'state', 'nonce']
    .map((name) => {
      const value = query.get(name)
      return value === null
        ? ''
        : `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`
    })
    .join('')
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mock IdP sign-in</title></head>
<body><main><h1>Mock IdP</h1>
<form method="post" action="/authorize">${hidden}
<label>IdP email <input name="email" type="email" required></label>
<label>IdP name <input name="name" type="text" value="Mock IdP User"></label>
<label><input name="email_verified" type="checkbox" value="true" checked> Email verified</label>
<button type="submit">Approve</button>
</form></main></body></html>`
}

async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', origin)
  const method = request.method ?? 'GET'

  if (url.pathname === '/.well-known/openid-configuration') {
    json(response, 200, {
      issuer: origin,
      authorization_endpoint: `${origin}/authorize`,
      token_endpoint: `${origin}/token`,
      userinfo_endpoint: `${origin}/userinfo`,
      jwks_uri: `${origin}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'email', 'profile'],
      claims_supported: ['sub', 'email', 'email_verified', 'name'],
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    })
    return
  }
  if (url.pathname === '/jwks' || url.pathname === '/google/certs') {
    json(response, 200, jwks)
    return
  }
  if (url.pathname === '/authorize' && method === 'GET') {
    if (url.searchParams.get('redirect_uri') === null) {
      json(response, 400, { error: 'invalid_request', error_description: 'redirect_uri' })
      return
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    response.end(authorizePage(url.searchParams))
    return
  }
  if (url.pathname === '/authorize' && method === 'POST') {
    const form = parseBody(request, await readBody(request))
    const redirectUri = form.get('redirect_uri')
    const email = form.get('email')
    if (redirectUri === null || email === null || email === '') {
      json(response, 400, { error: 'invalid_request' })
      return
    }
    const code = base64Url(randomBytes(24))
    codes.set(code, {
      profile: {
        sub: subjectFor(email),
        email,
        emailVerified: form.get('email_verified') === 'true',
        name: form.get('name') ?? email,
      },
      clientId: form.get('client_id') ?? 'unknown-client',
      nonce: form.get('nonce'),
    })
    const target = new URL(redirectUri)
    target.searchParams.set('code', code)
    const state = form.get('state')
    if (state !== null) {
      target.searchParams.set('state', state)
    }
    target.searchParams.set('iss', origin)
    response.writeHead(302, { location: target.toString() })
    response.end()
    return
  }
  if (url.pathname === '/token' && method === 'POST') {
    const form = parseBody(request, await readBody(request))
    const grant = codes.get(form.get('code') ?? '')
    if (grant === undefined) {
      json(response, 400, { error: 'invalid_grant' })
      return
    }
    codes.delete(form.get('code') ?? '')
    const accessToken = base64Url(randomBytes(24))
    accessTokens.set(accessToken, grant.profile)
    json(response, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'openid email profile',
      id_token: signJwt({
        ...idTokenClaims(grant.profile, grant.clientId, origin),
        ...(grant.nonce === null ? {} : { nonce: grant.nonce }),
      }),
    })
    return
  }
  if (url.pathname === '/userinfo') {
    const token = (request.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
    const profile = accessTokens.get(token)
    if (profile === undefined) {
      json(response, 401, { error: 'invalid_token' })
      return
    }
    json(response, 200, {
      sub: profile.sub,
      // Better Auth's generic profile mapping reads `id`.
      id: profile.sub,
      email: profile.email,
      email_verified: profile.emailVerified,
      name: profile.name,
    })
    return
  }
  // Test helper: a Google-shaped One Tap ID token signed by THIS key
  // (what Google's browser widget would hand the page).
  if (url.pathname === '/google/id-token' && method === 'POST') {
    const form = parseBody(request, await readBody(request))
    const email = form.get('email')
    const audience = form.get('aud')
    if (email === null || audience === null) {
      json(response, 400, { error: 'email and aud are required' })
      return
    }
    const profile: Profile = {
      sub: subjectFor(email),
      email,
      emailVerified: form.get('email_verified') !== 'false',
      name: form.get('name') ?? email,
    }
    json(response, 200, { credential: signJwt(idTokenClaims(profile, audience, googleIssuer)) })
    return
  }
  response.writeHead(404)
  response.end()
}

createServer((request, response) => {
  handle(request, response).catch((error: unknown) => {
    json(response, 500, { error: error instanceof Error ? error.message : 'mock idp failure' })
  })
}).listen(port, () => {
  process.stdout.write(`mock IdP listening on ${origin}\n`)
})
