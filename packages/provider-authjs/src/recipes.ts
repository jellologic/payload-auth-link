import { ResultAsync } from 'neverthrow'
import {
  isRecord,
  parseEmail,
  ProviderError,
  wellKnownProviderIds,
  type Email,
} from '@payload-auth-link/core'
import type { User } from '@auth/core/types'

/**
 * Builder-owned recipes for capabilities Auth.js has no native
 * primitive for (D7 maintenance tier): email OTP (CAP-2) and Google
 * One Tap (CAP-4). These are small, fully tested building blocks the
 * builder wires into their own providers — the plugin's linking gate
 * still decides what reaches Payload.
 */

// ---------------------------------------------------------------------------
// CAP-2: email OTP over the Auth.js Email provider
// ---------------------------------------------------------------------------

/**
 * Recommended OTP lifetime in seconds. Auth.js defaults verification
 * tokens to 24h, which is far too long for a 6-digit code: codes are
 * brute-forceable, so the recipe pairs this short `maxAge` with the
 * builder's verify-path rate limiter (attempt caps are builder-owned,
 * the SEC-13 precedent — a wrong guess neither consumes nor counts
 * against the code upstream).
 */
export const emailOtpMaxAgeSeconds = 300

/**
 * Generate one 6-digit email OTP code with a CSPRNG. Rejection
 * sampling keeps the distribution uniform over `000000`–`999999`
 * (never `Math.random`, never modulo bias). Suitable as an Email
 * provider's `generateVerificationToken`.
 */
export function generateEmailOtpCode(): string {
  const limit = 4_294_000_000 // largest multiple of 1e6 below 2^32
  const buffer = new Uint32Array(1)
  for (;;) {
    globalThis.crypto.getRandomValues(buffer)
    const value = buffer[0]
    if (value !== undefined && value < limit) {
      return String(value % 1_000_000).padStart(6, '0')
    }
  }
}

/** `generateVerificationToken` for an Auth.js Email provider (CAP-2). */
export const emailOtpVerificationToken = generateEmailOtpCode

/**
 * Build the callback URL an OTP form must submit to (spike S2: the
 * Auth.js email callback reads `token`/`email` from the QUERY STRING
 * only — a form POSTing them in the body fails with `Configuration`).
 * Use as the form's `action` (GET, or POST to this URL) — never put
 * the code in the POST body expecting it to be read.
 */
export function buildEmailOtpCallbackUrl(input: {
  /** Auth.js base path; defaults to this engine's `/api/authjs`. */
  readonly basePath?: string | undefined
  /** Email provider id, e.g. `resend` or `nodemailer`. */
  readonly providerId: string
  readonly email: string
  readonly code: string
  /** Post-sign-in destination Auth.js may return to. */
  readonly callbackUrl?: string | undefined
}): string {
  const basePath = input.basePath ?? '/api/authjs'
  const params = new URLSearchParams({ token: input.code, email: input.email })
  if (input.callbackUrl !== undefined) {
    params.set('callbackUrl', input.callbackUrl)
  }
  return `${basePath}/callback/${encodeURIComponent(input.providerId)}?${params.toString()}`
}

// ---------------------------------------------------------------------------
// CAP-4: Google One Tap over a Credentials provider
// ---------------------------------------------------------------------------

/** The Google ID-token facts the recipe trusts after verification. */
export type GoogleIdTokenProfile = {
  /** Google account id (`sub`), stable per account. */
  readonly providerUserId: string
  readonly email: Email
  readonly emailVerified: boolean
  readonly name: string | null
  readonly image: string | null
}

/** `verifyGoogleIdToken` wiring; every network/clock input is injectable. */
export type GoogleOneTapVerifyDeps = {
  /** Expected `aud`: your Google OAuth client id. Required, never defaulted. */
  readonly clientId: string
  /** JWKS fetcher; defaults to `fetch` against Google's certs endpoint. */
  readonly fetchJwks?: (() => Promise<unknown>) | undefined
  /** JWKS endpoint override (tests, proxies). */
  readonly jwksUrl?: string | undefined
  /** Clock for `exp`/`iat` checks; defaults to system time. */
  readonly now?: (() => Date) | undefined
}

const googleJwksUrl = 'https://www.googleapis.com/oauth2/v3/certs'
const googleIssuers = new Set(['accounts.google.com', 'https://accounts.google.com'])

function base64UrlToBytes(input: string): Uint8Array<ArrayBuffer> {
  const base64 = input.replaceAll('-', '+').replaceAll('_', '/')
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')
  const binary = globalThis.atob(padded)
  const bytes = new Uint8Array(new ArrayBuffer(binary.length))
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

function decodeJwtPart(part: string): unknown {
  const text = new TextDecoder().decode(base64UrlToBytes(part))
  return JSON.parse(text) as unknown
}

function findJwk(jwks: unknown, kid: string): JsonWebKey | null {
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) {
    return null
  }
  for (const key of jwks.keys) {
    if (!isRecord(key) || key.kid !== kid || key.kty !== 'RSA') {
      continue
    }
    // Rebuild the JWK from narrowed string fields only — never hand
    // the raw record to WebCrypto.
    if (typeof key.n !== 'string' || typeof key.e !== 'string') {
      continue
    }
    return {
      kty: 'RSA',
      n: key.n,
      e: key.e,
      ...(typeof key.alg === 'string' ? { alg: key.alg } : {}),
      ...(typeof key.use === 'string' ? { use: key.use } : {}),
    }
  }
  return null
}

const providerId = wellKnownProviderIds.authjs

/**
 * Verify a Google One Tap ID token locally: RS256 signature against
 * Google's JWKS (selected by `kid`), then `iss`, `aud`, and `exp`.
 * No Google callout beyond the public keys, and no claim is read
 * before the signature verifies. Every failure is a typed
 * `ProviderError` — callers treat any error as "not signed in".
 */
export function verifyGoogleIdToken(
  token: string,
  deps: GoogleOneTapVerifyDeps
): ResultAsync<GoogleIdTokenProfile, ProviderError> {
  return ResultAsync.fromPromise(
    (async (): Promise<GoogleIdTokenProfile> => {
      const parts = token.split('.')
      if (parts.length !== 3) {
        throw new Error('id token is not a JWT')
      }
      const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string]
      const header = decodeJwtPart(encodedHeader)
      if (!isRecord(header) || header.alg !== 'RS256' || typeof header.kid !== 'string') {
        throw new Error('id token header is not RS256 with a kid')
      }
      const jwks: unknown =
        deps.fetchJwks !== undefined
          ? await deps.fetchJwks()
          : await (await fetch(deps.jwksUrl ?? googleJwksUrl)).json()
      const jwk = findJwk(jwks, header.kid)
      if (jwk === null) {
        throw new Error('no matching Google signing key')
      }
      const key = await globalThis.crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      )
      const signingInput = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
      const valid = await globalThis.crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        key,
        base64UrlToBytes(encodedSignature),
        signingInput
      )
      if (!valid) {
        throw new Error('id token signature does not verify')
      }
      const payload = decodeJwtPart(encodedPayload)
      if (!isRecord(payload)) {
        throw new Error('id token payload is malformed')
      }
      if (typeof payload.iss !== 'string' || !googleIssuers.has(payload.iss)) {
        throw new Error('id token issuer is not Google')
      }
      if (payload.aud !== deps.clientId) {
        throw new Error('id token audience does not match the client id')
      }
      const nowSeconds = Math.floor((deps.now?.() ?? new Date()).getTime() / 1000)
      if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) {
        throw new Error('id token is expired')
      }
      if (typeof payload.sub !== 'string' || payload.sub === '') {
        throw new Error('id token subject is missing')
      }
      const parsedEmail = parseEmail(payload.email)
      if (parsedEmail.isErr()) {
        throw new Error('id token email is missing or invalid')
      }
      return {
        providerUserId: payload.sub,
        email: parsedEmail.value,
        emailVerified: payload.email_verified === true,
        name: typeof payload.name === 'string' ? payload.name : null,
        image: typeof payload.picture === 'string' ? payload.picture : null,
      }
    })(),
    (cause) => new ProviderError(providerId, 'verifyGoogleIdToken', { cause })
  )
}

/** `createGoogleOneTapAuthorize` wiring. */
export type GoogleOneTapAuthorizeDeps = GoogleOneTapVerifyDeps & {
  /**
   * Resolve the verified Google profile to an Auth.js user (builder
   * owns persistence — e.g. the adapter's `getUserByEmail` +
   * `createUser`). Return `null` to refuse. Only ever called with a
   * signature-verified profile whose `emailVerified` is `true`:
   * One Tap sessions link by email, so an unverified Google email
   * must never resolve to a user here either.
   */
  readonly upsertUser: (profile: GoogleIdTokenProfile) => Promise<User | null>
}

/**
 * Build the `authorize` callback for a Credentials provider backing
 * Google One Tap (CAP-4 recipe). Google's browser flow posts the ID
 * token as the `credential` field; anything else (missing token,
 * bad signature, wrong audience, unverified email) resolves to
 * `null` — Credentials' "not signed in", never an exception leaking
 * which check failed. Credentials sessions are JWT-only; the engine
 * already enforces that pairing.
 */
export function createGoogleOneTapAuthorize(
  deps: GoogleOneTapAuthorizeDeps
): (credentials: Record<string, unknown> | undefined) => Promise<User | null> {
  return async (credentials) => {
    const credential = credentials?.credential
    if (typeof credential !== 'string' || credential === '') {
      return null
    }
    const verified = await verifyGoogleIdToken(credential, deps)
    if (verified.isErr() || !verified.value.emailVerified) {
      return null
    }
    try {
      return await deps.upsertUser(verified.value)
    } catch {
      // Storage faults surface as a failed sign-in, not a 500 with
      // internals; the builder logs inside `upsertUser` if needed.
      return null
    }
  }
}
