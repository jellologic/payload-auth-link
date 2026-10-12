import { describe, expect, it } from 'vitest'
import { InvalidConfigError } from '../errors.js'
import {
  csrfHeaderName,
  defaultSessionEndpointPath,
  normalizeBaseUrl,
  parseSessionResponse,
  parseSessionUser,
  resolveOrigin,
} from '../http.js'

const valid = {
  id: 'user-1',
  collection: 'users',
  email: 'user@example.com',
  roles: ['member', 'admin'],
}

describe('wire constants', () => {
  it('pins the CSRF header and session endpoint path', () => {
    expect(csrfHeaderName).toBe('x-auth-link-csrf')
    expect(defaultSessionEndpointPath).toBe('/api/auth-link/session')
  })
})

describe('parseSessionUser', () => {
  it('narrows a valid envelope user', () => {
    expect(parseSessionUser(valid)).toEqual(valid)
  })

  it('fails closed on non-objects', () => {
    for (const value of [null, undefined, 42, 'user', []]) {
      expect(parseSessionUser(value)).toBeNull()
    }
  })

  it('fails closed on bad id or collection', () => {
    expect(parseSessionUser({ ...valid, id: '' })).toBeNull()
    expect(parseSessionUser({ ...valid, id: 42 })).toBeNull()
    expect(parseSessionUser({ ...valid, collection: '' })).toBeNull()
    expect(parseSessionUser({ ...valid, collection: undefined })).toBeNull()
  })

  it('fails closed on invalid email', () => {
    expect(parseSessionUser({ ...valid, email: 'not-an-email' })).toBeNull()
    expect(parseSessionUser({ ...valid, email: undefined })).toBeNull()
  })

  it('fails closed on malformed roles', () => {
    expect(parseSessionUser({ ...valid, roles: 'admin' })).toBeNull()
    expect(parseSessionUser({ ...valid, roles: ['admin', 'Bogus'] })).toBeNull()
    expect(parseSessionUser({ ...valid, roles: ['admin', 42] })).toBeNull()
    expect(parseSessionUser({ ...valid })).not.toBeNull()
  })
})

describe('normalizeBaseUrl', () => {
  it('returns valid http(s) origins unchanged', () => {
    expect(normalizeBaseUrl('https://app.example.com')).toBe('https://app.example.com')
    expect(normalizeBaseUrl('http://localhost:3000')).toBe('http://localhost:3000')
  })

  it('throws InvalidConfigError on malformed origins', () => {
    for (const bad of ['nope', '', 'ftp://files.example.com', '//host-only', '/relative/path']) {
      expect(() => normalizeBaseUrl(bad)).toThrow(InvalidConfigError)
    }
  })
})

describe('resolveOrigin', () => {
  const forwarded = () =>
    new Headers({
      'x-forwarded-host': 'app.example.com',
      'x-forwarded-proto': 'https',
    })

  it('prefers the configured baseUrl over headers', () => {
    expect(
      resolveOrigin({
        baseUrl: 'https://app.example.com',
        headers: forwarded(),
        allowHostFallback: true,
      })
    ).toBe('https://app.example.com')
  })

  it('derives the origin from forwarded headers when allowed', () => {
    expect(resolveOrigin({ headers: forwarded(), allowHostFallback: true })).toBe(
      'https://app.example.com'
    )
    expect(
      resolveOrigin({ headers: new Headers({ host: 'localhost:3000' }), allowHostFallback: true })
    ).toBe('http://localhost:3000')
  })

  it('throws when the fallback is disabled without baseUrl', () => {
    expect(() => resolveOrigin({ headers: forwarded(), allowHostFallback: false })).toThrow(
      InvalidConfigError
    )
  })

  it('throws when no host header and no baseUrl', () => {
    expect(() => resolveOrigin({ headers: new Headers(), allowHostFallback: true })).toThrow(
      InvalidConfigError
    )
  })
})

describe('parseSessionResponse', () => {
  const envelope = (user: unknown): Pick<Response, 'ok' | 'json'> => ({
    ok: true,
    json: () => Promise.resolve({ user }),
  })

  it('returns the user for a valid ok envelope', async () => {
    await expect(parseSessionResponse(envelope(valid))).resolves.toEqual(valid)
  })

  it('returns null for non-ok responses', async () => {
    await expect(
      parseSessionResponse({ ok: false, json: () => Promise.resolve({ user: valid }) })
    ).resolves.toBeNull()
  })

  it('returns null when the body is not valid JSON', async () => {
    await expect(
      parseSessionResponse({
        ok: true,
        json: () => Promise.reject(new SyntaxError('Unexpected end of JSON input')),
      })
    ).resolves.toBeNull()
  })

  it('returns null for malformed envelopes', async () => {
    for (const body of [null, 42, 'nope', [], { user: null }, { user: { id: 1 } }, {}]) {
      await expect(
        parseSessionResponse({ ok: true, json: () => Promise.resolve(body) })
      ).resolves.toBeNull()
    }
  })
})
