import { describe, expect, it } from 'vitest'
import { InvalidConfigError } from '../errors.js'
import {
  csrfHeaderName,
  defaultSessionEndpointPath,
  normalizeBaseUrl,
  parseGuestResponse,
  parseSessionGuest,
  parseSessionResponse,
  parseSessionUser,
  resolveOrigin,
  type SessionUserDegradeReason,
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

  it('parses old payloads without the PORT-4 fields, leaving them absent', () => {
    const parsed = parseSessionUser({ ...valid })
    expect(parsed).toEqual(valid)
    expect(parsed).not.toHaveProperty('assurance')
    expect(parsed).not.toHaveProperty('actor')
    expect(parsed).not.toHaveProperty('organizationId')
  })

  it('round-trips the PORT-4 fields through JSON', () => {
    const withFacts = {
      ...valid,
      assurance: { methods: ['password'], mfa: true },
      actor: { kind: 'payload-user', providerUserId: 'operator-1', userId: 'user-9' },
      organizationId: 'org-1',
    }
    expect(parseSessionUser(JSON.parse(JSON.stringify(withFacts)) as unknown)).toEqual(withFacts)
  })

  it('normalizes the pre-CAP-8b actor form to provider-only', () => {
    const parsed = parseSessionUser({ ...valid, actor: { providerUserId: 'operator-1' } })
    expect(parsed?.actor).toEqual({ kind: 'provider-only', providerUserId: 'operator-1' })
  })

  it("preserves 'unknown' assurance as data instead of dropping it", () => {
    const parsed = parseSessionUser({
      ...valid,
      assurance: { methods: 'unknown', mfa: 'unknown' },
    })
    expect(parsed?.assurance).toEqual({ methods: 'unknown', mfa: 'unknown' })
  })

  it('normalizes explicit null actor/organizationId to absent', () => {
    const parsed = parseSessionUser({ ...valid, actor: null, organizationId: null })
    expect(parsed).toEqual(valid)
    expect(parsed).not.toHaveProperty('actor')
    expect(parsed).not.toHaveProperty('organizationId')
  })

  it('ignores unknown keys inside assurance/actor (forward compatibility)', () => {
    const parsed = parseSessionUser({
      ...valid,
      assurance: { methods: ['password'], mfa: true, level: 3 },
      actor: { kind: 'payload-user', providerUserId: 'op-1', userId: 'user-9', reason: 's' },
      organizationId: 'org-1',
    })
    expect(parsed?.assurance).toEqual({ methods: ['password'], mfa: true })
    expect(parsed?.actor).toEqual({
      kind: 'payload-user',
      providerUserId: 'op-1',
      userId: 'user-9',
    })
    const legacy = parseSessionUser({
      ...valid,
      actor: { providerUserId: 'op-1', reason: 'support' },
    })
    expect(legacy?.actor).toEqual({ kind: 'provider-only', providerUserId: 'op-1' })
    const providerOnly = parseSessionUser({
      ...valid,
      actor: { kind: 'provider-only', providerUserId: 'op-1', userId: 'ignored' },
    })
    expect(providerOnly?.actor).toEqual({ kind: 'provider-only', providerUserId: 'op-1' })
  })

  it('degrades malformed OPTIONAL fields fail-closed-for-policy, never whole-user null', () => {
    for (const assurance of [
      null,
      { methods: ['telepathy'], mfa: true },
      { methods: 'password', mfa: true },
      { methods: ['password'], mfa: 'yes' },
      'strong',
    ]) {
      const parsed = parseSessionUser({ ...valid, assurance })
      expect(parsed).not.toBeNull()
      // 'unknown' never satisfies a policy requiring proof.
      expect(parsed?.assurance).toEqual({ methods: 'unknown', mfa: 'unknown' })
    }
    for (const actor of [{ providerUserId: '' }, 'operator-1', 42]) {
      const parsed = parseSessionUser({ ...valid, actor })
      expect(parsed).not.toBeNull()
      expect(parsed).not.toHaveProperty('actor')
    }
    // Actors carrying a valid provider id but an unusable shape
    // (unknown future kind, missing Payload userId) degrade to
    // provider-only: the operator stays named, never upgraded.
    for (const actor of [
      { kind: 'ghost', providerUserId: 'op-1' },
      { kind: 'payload-user', providerUserId: 'op-1' },
      { kind: 'payload-user', providerUserId: 'op-1', userId: '' },
    ]) {
      expect(parseSessionUser({ ...valid, actor })?.actor).toEqual({
        kind: 'provider-only',
        providerUserId: 'op-1',
      })
    }
    for (const organizationId of ['', 42]) {
      const parsed = parseSessionUser({ ...valid, organizationId })
      expect(parsed).not.toBeNull()
      expect(parsed).not.toHaveProperty('organizationId')
    }
  })

  it('reports every degradation through onDegrade with a typed reason (B20)', () => {
    const reasons: SessionUserDegradeReason[] = []
    const onDegrade = (reason: SessionUserDegradeReason): void => {
      reasons.push(reason)
    }
    // Unknown AuthMethod from a newer server: assurance degrades to
    // 'unknown' AND the skew is observable, never silent.
    const parsed = parseSessionUser(
      {
        ...valid,
        assurance: { methods: ['quantum-entanglement'], mfa: true },
        actor: 42,
        organizationId: 42,
      },
      { onDegrade }
    )
    expect(parsed?.assurance).toEqual({ methods: 'unknown', mfa: 'unknown' })
    expect(reasons).toEqual(['assurance-malformed', 'actor-malformed', 'organization-malformed'])

    reasons.length = 0
    parseSessionUser(valid, { onDegrade })
    parseSessionUser({ ...valid, assurance: { methods: ['password'], mfa: true } }, { onDegrade })
    // Absent and explicitly-null optionals are not degradations.
    parseSessionUser({ ...valid, actor: null, organizationId: null }, { onDegrade })
    expect(reasons).toEqual([])
  })

  it('keeps core identity fields strict even when optionals are malformed', () => {
    expect(
      parseSessionUser({ ...valid, email: 'bad', assurance: { methods: [], mfa: true } })
    ).toBeNull()
    expect(parseSessionUser({ ...valid, roles: ['Bogus'], actor: 'x' })).toBeNull()
    expect(parseSessionUser({ ...valid, id: '' })).toBeNull()
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

  it('derives the origin from forwarded headers only under trustProxy', () => {
    expect(resolveOrigin({ headers: forwarded(), allowHostFallback: true, trustProxy: true })).toBe(
      'https://app.example.com'
    )
    const spoofed = new Headers({ host: 'localhost:3000', 'x-forwarded-host': 'evil.example.com' })
    expect(resolveOrigin({ headers: spoofed, allowHostFallback: true })).toBe(
      'http://localhost:3000'
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

  it('rejects non-http schemes, malformed hosts, and hosts outside the allowlist', () => {
    const bad: Array<Record<string, string>> = [
      { host: 'localhost', 'x-forwarded-proto': 'file' },
      { host: 'user@localhost' },
      { host: 'localhost/path' },
      { host: 'localhost?x' },
      { host: 'evil.example.com' },
    ]
    for (const entries of bad) {
      expect(() =>
        resolveOrigin({
          headers: new Headers(entries),
          allowHostFallback: true,
          trustProxy: true,
          allowedHosts: ['localhost'],
        })
      ).toThrow(InvalidConfigError)
    }
    expect(
      resolveOrigin({
        headers: new Headers({ host: 'LOCALHOST:3000', 'x-forwarded-proto': 'HTTPS' }),
        allowHostFallback: true,
        trustProxy: true,
        allowedHosts: ['localhost'],
      })
    ).toBe('https://localhost:3000')
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

describe('guest envelope (CAP-10)', () => {
  const guest = { id: 'anon-1', providerId: 'better-auth', expiresAt: '2026-01-01T00:00:00.000Z' }

  it('parses a guest only from a user:null envelope', async () => {
    await expect(
      parseGuestResponse({ ok: true, json: () => Promise.resolve({ user: null, guest }) })
    ).resolves.toEqual(guest)
    // A live user wins: no guest is reported beside one.
    await expect(
      parseGuestResponse({ ok: true, json: () => Promise.resolve({ user: valid, guest }) })
    ).resolves.toBeNull()
    await expect(
      parseGuestResponse({ ok: false, json: () => Promise.resolve({ user: null, guest }) })
    ).resolves.toBeNull()
    expect(parseSessionGuest({ id: '', providerId: 'x', expiresAt: 'y' })).toBeNull()
    expect(parseSessionGuest(null)).toBeNull()
  })
})
