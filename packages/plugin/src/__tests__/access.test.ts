import { InvalidConfigError } from '@payload-auth-link/core'
import type { PayloadRequest } from 'payload'
import { describe, expect, it } from 'vitest'
import {
  denyWhileImpersonating,
  denyWithoutMfa,
  forbidden,
  sessionMfaSatisfied,
  impersonationActorFromRequest,
  impersonationStateFromRequest,
  isImpersonating,
  isSameOrigin,
  passesCsrf,
  passesCsrfForChannel,
  unauthorized,
  type ImpersonationOperation,
} from '../access.js'

const baseUrl = 'http://auth-link.test'

describe('isSameOrigin', () => {
  it('compares origins strictly', () => {
    expect(isSameOrigin('http://auth-link.test/login', baseUrl)).toBe(true)
    expect(isSameOrigin('https://auth-link.test/', baseUrl)).toBe(false)
    expect(isSameOrigin('http://evil.test/', baseUrl)).toBe(false)
    expect(isSameOrigin('not-a-url', baseUrl)).toBe(false)
    expect(isSameOrigin('http://auth-link.test/', 'not-a-url')).toBe(false)
  })
})

describe('passesCsrf', () => {
  it('accepts the custom header', () => {
    expect(passesCsrf(new Headers({ 'x-auth-link-csrf': '1' }), baseUrl)).toBe(true)
  })

  it('accepts a matching Origin', () => {
    expect(passesCsrf(new Headers({ origin: 'http://auth-link.test' }), baseUrl)).toBe(true)
  })

  it('fails closed otherwise', () => {
    expect(passesCsrf(new Headers(), baseUrl)).toBe(false)
    expect(passesCsrf(new Headers({ origin: 'https://evil.test' }), baseUrl)).toBe(false)
    expect(passesCsrf(new Headers({ 'x-auth-link-csrf': 'yes' }), baseUrl)).toBe(false)
  })
})

describe('passesCsrfForChannel (CAP-13b)', () => {
  const bearer = new Headers({ authorization: 'Bearer token-1' })

  it('skips the origin check for bearer presentation only when bearer is admitted', () => {
    expect(passesCsrfForChannel(bearer, baseUrl, ['cookie', 'bearer'])).toBe(true)
    expect(passesCsrfForChannel(bearer, baseUrl, ['cookie'])).toBe(false)
    // No bearer token presented: cookie rules apply even when admitted.
    expect(passesCsrfForChannel(new Headers(), baseUrl, ['cookie', 'bearer'])).toBe(false)
    expect(
      passesCsrfForChannel(new Headers({ origin: baseUrl }), baseUrl, ['cookie', 'bearer'])
    ).toBe(true)
    expect(
      passesCsrfForChannel(new Headers({ authorization: 'Basic abc' }), baseUrl, ['bearer'])
    ).toBe(false)
  })
})

function requestWith(user: unknown): PayloadRequest {
  return { user } as unknown as PayloadRequest
}

const impersonatedUser = {
  id: 'user-1',
  collection: 'users',
  email: 'target@test.dev',
  roles: ['user'],
  actor: { kind: 'payload-user', providerUserId: 'op-1', userId: 'user-9' },
}

const plainUser = {
  id: 'user-1',
  collection: 'users',
  email: 'target@test.dev',
  roles: ['user'],
}

describe('impersonationActorFromRequest (CAP-8b)', () => {
  it('reads the resolved actor off the strategy user', () => {
    expect(impersonationActorFromRequest(requestWith(impersonatedUser))).toEqual({
      kind: 'payload-user',
      providerUserId: 'op-1',
      userId: 'user-9',
    })
  })

  it('treats provider-only actors as impersonating too (fail closed)', () => {
    const user = { ...plainUser, actor: { kind: 'provider-only', providerUserId: 'op-2' } }
    expect(impersonationActorFromRequest(requestWith(user))).toEqual({
      kind: 'provider-only',
      providerUserId: 'op-2',
    })
  })

  it('returns null for plain, anonymous, and malformed users', () => {
    expect(impersonationActorFromRequest(requestWith(plainUser))).toBeNull()
    expect(impersonationActorFromRequest(requestWith(null))).toBeNull()
    expect(impersonationActorFromRequest(requestWith(undefined))).toBeNull()
    expect(impersonationActorFromRequest(requestWith({ id: 42 }))).toBeNull()
  })

  it('does not require wire-valid identity fields to see the actor (server extraction)', () => {
    // A Payload doc user (numeric id, no wire roles/email parse) still
    // yields its actor: server authz must not ride the client parser.
    const docUser = { id: 7, actor: { kind: 'provider-only', providerUserId: 'op-3' } }
    expect(impersonationActorFromRequest(requestWith(docUser))).toEqual({
      kind: 'provider-only',
      providerUserId: 'op-3',
    })
    expect(isImpersonating(requestWith(docUser))).toBe(true)
  })

  it('FAIL-CLOSED: a present but unparseable actor still counts as impersonating', () => {
    for (const actor of [
      'operator-1',
      42,
      { kind: 'ghost', providerUserId: 'op-1' },
      { kind: 'payload-user', providerUserId: 'op-1' },
      { providerUserId: '' },
      {},
    ]) {
      const req = requestWith({ ...plainUser, actor })
      expect(isImpersonating(req)).toBe(true)
      expect(impersonationStateFromRequest(req)).toEqual({ kind: 'malformed-actor' })
      // No fabricated attribution for a malformed actor.
      expect(impersonationActorFromRequest(req)).toBeNull()
    }
    expect(isImpersonating(requestWith(plainUser))).toBe(false)
    expect(isImpersonating(requestWith({ ...plainUser, actor: null }))).toBe(false)
    expect(isImpersonating(requestWith(null))).toBe(false)
  })
})

describe('denyWhileImpersonating (CAP-8b / D5)', () => {
  it('by default denies admin and writes while impersonating, allows reads', async () => {
    const access = denyWhileImpersonating()
    const req = requestWith(impersonatedUser)
    expect(await access.admin?.({ req })).toBe(false)
    expect(await access.update?.({ req })).toBe(false)
    expect(await access.create?.({ req })).toBe(false)
    expect(await access.delete?.({ req })).toBe(false)
    expect(await access.unlock?.({ req })).toBe(false)
    expect(await access.read?.({ req })).toBe(true)
    expect(await access.readVersions?.({ req })).toBe(true)
  })

  it('allows everything for a non-impersonated request', async () => {
    const access = denyWhileImpersonating()
    const req = requestWith(plainUser)
    expect(await access.admin?.({ req })).toBe(true)
    expect(await access.update?.({ req })).toBe(true)
    expect(await access.read?.({ req })).toBe(true)
  })

  it('honors a custom operation list', async () => {
    const access = denyWhileImpersonating(['read'])
    const req = requestWith(impersonatedUser)
    expect(await access.read?.({ req })).toBe(false)
    expect(await access.update?.({ req })).toBe(true)
    expect(await access.admin?.({ req })).toBe(true)
  })

  it('FAIL-CLOSED: denies while the actor is present but malformed', async () => {
    const access = denyWhileImpersonating()
    const req = requestWith({ ...plainUser, actor: 'operator-1' })
    expect(await access.admin?.({ req })).toBe(false)
    expect(await access.update?.({ req })).toBe(false)
    expect(await access.create?.({ req })).toBe(false)
  })

  it('fails fast on an unknown operation name', () => {
    const bogus = 'publish' as unknown as ImpersonationOperation
    expect(() => denyWhileImpersonating([bogus])).toThrow(InvalidConfigError)
  })
})

describe('denyWithoutMfa (CAP-6)', () => {
  const mfaUser = { ...plainUser, assurance: { methods: ['password'], mfa: true } }
  const unknownUser = { ...plainUser, assurance: { methods: 'unknown', mfa: 'unknown' } }

  it('allows only literal mfa:true; absent or malformed assurance fails closed', async () => {
    const access = denyWithoutMfa()
    expect(await access.admin?.({ req: requestWith(mfaUser) })).toBe(true)
    expect(await access.update?.({ req: requestWith(mfaUser) })).toBe(true)
    expect(await access.admin?.({ req: requestWith(unknownUser) })).toBe(false)
    expect(await access.update?.({ req: requestWith(plainUser) })).toBe(false)
    expect(await access.update?.({ req: requestWith({ ...plainUser, assurance: 'yes' }) })).toBe(
      false
    )
    expect(await access.read?.({ req: requestWith(plainUser) })).toBe(true)
    expect(sessionMfaSatisfied(requestWith(mfaUser))).toBe(true)
    expect(sessionMfaSatisfied(requestWith(null))).toBe(false)
  })

  it('fails fast on an unknown operation name', () => {
    const bogus = 'publish' as unknown as ImpersonationOperation
    expect(() => denyWithoutMfa([bogus])).toThrow(InvalidConfigError)
  })
})

describe('error responses', () => {
  it('uses 401 and 403 with bodies', async () => {
    expect(unauthorized().status).toBe(401)
    expect(forbidden().status).toBe(403)
    expect(await unauthorized().json()).toEqual({ error: 'authentication required' })
  })
})
