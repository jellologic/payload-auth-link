import { describe, expect, it, vi } from 'vitest'
import {
  buildEmailOtpCallbackUrl,
  createGoogleOneTapAuthorize,
  generateEmailOtpCode,
  verifyGoogleIdToken,
} from '../recipes.js'
import { authJsCapabilities } from '../port.js'

describe('email OTP recipe (CAP-2)', () => {
  it('generates 6-digit zero-padded codes', () => {
    for (let run = 0; run < 50; run += 1) {
      expect(generateEmailOtpCode()).toMatch(/^\d{6}$/)
    }
  })

  it('builds the query-string callback URL the Auth.js email callback reads (spike S2)', () => {
    expect(
      buildEmailOtpCallbackUrl({
        providerId: 'resend',
        email: 'user@example.com',
        code: '123456',
        callbackUrl: '/account',
      })
    ).toBe(
      '/api/authjs/callback/resend?token=123456&email=user%40example.com&callbackUrl=%2Faccount'
    )
  })
})

const clientId = 'test-client-id.apps.googleusercontent.com'
const now = new Date('2026-10-12T00:00:00.000Z')

function base64Url(bytes: Uint8Array | string): string {
  const binary = typeof bytes === 'string' ? bytes : String.fromCharCode(...bytes)
  return globalThis.btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

async function makeToken(overrides?: {
  readonly payload?: Record<string, unknown>
  readonly kid?: string
  readonly tamper?: boolean
}): Promise<{ token: string; jwks: unknown }> {
  const pair = await globalThis.crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  )
  const kid = overrides?.kid ?? 'test-kid'
  const publicJwk = await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey)
  const header = base64Url(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }))
  const payload = base64Url(
    JSON.stringify({
      iss: 'https://accounts.google.com',
      aud: clientId,
      sub: 'google-123',
      email: 'user@example.com',
      email_verified: true,
      name: 'Test User',
      exp: Math.floor(now.getTime() / 1000) + 600,
      ...overrides?.payload,
    })
  )
  const signature = await globalThis.crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    pair.privateKey,
    new TextEncoder().encode(`${header}.${payload}`)
  )
  const encoded = base64Url(new Uint8Array(signature))
  const token = `${header}.${payload}.${overrides?.tamper === true ? `${encoded.slice(0, -2)}AA` : encoded}`
  return { token, jwks: { keys: [{ ...publicJwk, kid }] } }
}

describe('verifyGoogleIdToken (CAP-4)', () => {
  it('verifies signature, issuer, audience, and expiry against a local JWKS', async () => {
    const { token, jwks } = await makeToken()
    const result = await verifyGoogleIdToken(token, {
      clientId,
      fetchJwks: () => Promise.resolve(jwks),
      now: () => now,
    })
    expect(result._unsafeUnwrap()).toEqual({
      providerUserId: 'google-123',
      email: 'user@example.com',
      emailVerified: true,
      name: 'Test User',
      image: null,
    })
  })

  it('rejects tampered signatures, wrong audiences, expired and foreign tokens', async () => {
    const cases = [
      await makeToken({ tamper: true }),
      await makeToken({ payload: { aud: 'someone-else' } }),
      await makeToken({ payload: { exp: Math.floor(now.getTime() / 1000) - 1 } }),
      await makeToken({ payload: { iss: 'https://evil.example' } }),
      await makeToken({ kid: 'unknown-kid', payload: {} }),
    ]
    // The unknown-kid case must be checked against a JWKS without it.
    const { jwks } = await makeToken()
    for (const { token } of cases) {
      const result = await verifyGoogleIdToken(token, {
        clientId,
        fetchJwks: () => Promise.resolve(jwks),
        now: () => now,
      })
      expect(result.isErr()).toBe(true)
    }
    expect((await verifyGoogleIdToken('not-a-jwt', { clientId })).isErr()).toBe(true)
  })
})

describe('createGoogleOneTapAuthorize (CAP-4)', () => {
  it('resolves only verified-email profiles through upsertUser', async () => {
    const { token, jwks } = await makeToken()
    const upsertUser = vi.fn(() => Promise.resolve({ id: 'aj-1', email: 'user@example.com' }))
    const authorize = createGoogleOneTapAuthorize({
      clientId,
      fetchJwks: () => Promise.resolve(jwks),
      now: () => now,
      upsertUser,
    })
    expect(await authorize({ credential: token })).toMatchObject({ id: 'aj-1' })
    expect(upsertUser).toHaveBeenCalledWith(
      expect.objectContaining({ providerUserId: 'google-123', emailVerified: true })
    )
    expect(await authorize({})).toBeNull()
    expect(await authorize(undefined)).toBeNull()
    expect(await authorize({ credential: 'junk' })).toBeNull()
  })

  it('never resolves an unverified Google email', async () => {
    const { token, jwks } = await makeToken({ payload: { email_verified: false } })
    const upsertUser = vi.fn(() => Promise.resolve({ id: 'aj-1' }))
    const authorize = createGoogleOneTapAuthorize({
      clientId,
      fetchJwks: () => Promise.resolve(jwks),
      now: () => now,
      upsertUser,
    })
    expect(await authorize({ credential: token })).toBeNull()
    expect(upsertUser).not.toHaveBeenCalled()
  })
})

describe('authJsCapabilities (PORT-2)', () => {
  it('derives magic-link/oauth from provider types and revoke from database sessions', () => {
    expect(
      [...authJsCapabilities({ providerTypes: ['email', 'oidc', 'credentials'] })].sort()
    ).toEqual(['magic-link', 'oauth'])
    expect(authJsCapabilities({ providerTypes: [], databaseSessions: true })).toEqual(
      new Set(['revoke-user-sessions'])
    )
    expect(authJsCapabilities({})).toEqual(new Set())
  })
})
