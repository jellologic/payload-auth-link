import { okAsync } from 'neverthrow'
import { describe, expect, it } from 'vitest'
import { parseEmail } from '../email.js'
import {
  defineProviderId,
  type Capability,
  type IdentityProviderPort,
  type ProviderSession,
} from '../ports.js'
import {
  assertProviderConformance,
  checkProviderConformance,
  ProviderConformanceError,
  type ProviderConformanceFactory,
  type ProviderConformanceSubject,
} from '../testing/index.js'

const verifiedHeaders = new Headers({ cookie: 'fake_session=tok-verified' })
const unverifiedHeaders = new Headers({ cookie: 'fake_session=tok-unverified' })
const impersonatedHeaders = new Headers({ cookie: 'fake_session=tok-impersonated' })

type Breakage =
  | 'alias-drift'
  | 'wrong-channel'
  | 'drop-actor'
  | 'revoke-noop'
  | 'declare-revoke-all-only'
  | 'implement-revoke-all-only'
  | 'unknown-capability'
  | 'overclaim-capabilities'
  | 'malformed-session'

function emailOf(value: string) {
  const parsed = parseEmail(value)
  if (parsed.isErr()) throw new Error('test email must parse')
  return parsed.value
}

function sessionFor(token: string, breakage?: Breakage): ProviderSession {
  const verified = token !== 'tok-unverified'
  const email = emailOf('user@example.com')
  const base: ProviderSession = {
    sessionId: token,
    providerUserId: 'provider-user-1',
    email,
    emailVerified: breakage === 'alias-drift' ? !verified : verified,
    expiresAt: new Date('2026-02-01T00:00:00.000Z'),
    identity: { email: { value: email, verified }, phone: null, anonymous: false },
    assurance: { methods: 'unknown', mfa: 'unknown' },
    actor:
      token === 'tok-impersonated' && breakage !== 'drop-actor'
        ? { providerUserId: 'operator-1' }
        : null,
    organizationId: null,
    channel: breakage === 'wrong-channel' ? 'bearer' : 'cookie',
  }
  if (breakage === 'malformed-session') {
    const broken: unknown = { ...base, expiresAt: 'not-a-date' }
    return broken as ProviderSession
  }
  return base
}

function fakeFactory(
  breakage?: Breakage,
  opts: { bestEffortRevoke?: boolean; omitImpersonated?: boolean } = {}
): ProviderConformanceFactory {
  return (): ProviderConformanceSubject => {
    const live = new Set(['tok-verified', 'tok-unverified', 'tok-impersonated'])
    const capabilities = new Set<Capability>(['impersonation'])
    if (breakage === 'declare-revoke-all-only') capabilities.add('revoke-user-sessions')
    if (breakage === 'unknown-capability') {
      ;(capabilities as Set<string>).add('teleport')
    }
    if (breakage === 'overclaim-capabilities') {
      // Declares capabilities its sessions never evidence: phone is
      // always null, anonymous always false, methods 'unknown'.
      for (const capability of ['phone', 'oauth', 'passkey', 'magic-link', 'anonymous'] as const) {
        capabilities.add(capability)
      }
    }
    const port: IdentityProviderPort = {
      id: defineProviderId('fake'),
      capabilities,
      sessionCookieNames: ['fake_session'],
      getSession: (headers) => {
        const match = /fake_session=([^;]+)/.exec(headers.get('cookie') ?? '')
        const token = match?.[1]
        if (token === undefined || !live.has(token)) return okAsync(null)
        return okAsync(sessionFor(token, breakage))
      },
      revokeSession: (sessionId) => {
        if (breakage !== 'revoke-noop') live.delete(sessionId)
        return okAsync(undefined)
      },
      ...(breakage === 'implement-revoke-all-only'
        ? {
            revokeUserSessions: () => {
              live.clear()
              return okAsync(undefined)
            },
          }
        : {}),
    }
    const expected = {
      providerUserId: 'provider-user-1',
      email: 'user@example.com',
      emailVerified: true,
      channel: 'cookie' as const,
      methods: 'unknown' as const,
      mfa: 'unknown' as const,
      organizationId: null,
    }
    return {
      port,
      scenarios: {
        session: { headers: verifiedHeaders, expected },
        unverifiedSession: {
          headers: unverifiedHeaders,
          expected: { ...expected, emailVerified: false },
        },
        ...(opts.omitImpersonated === true
          ? {}
          : {
              impersonatedSession: {
                headers: impersonatedHeaders,
                expectedActorProviderUserId: 'operator-1',
              },
            }),
        noSession: { headers: new Headers() },
        ...(opts.bestEffortRevoke === true ? { revoke: { mode: 'best-effort' as const } } : {}),
      },
    }
  }
}

describe('provider conformance kit', () => {
  it('passes a conforming fake port', async () => {
    await expect(assertProviderConformance(fakeFactory())).resolves.toBeUndefined()
    await expect(checkProviderConformance(fakeFactory())).resolves.toEqual([])
  })

  it('flags deprecated-alias drift from the email claim', async () => {
    const violations = await checkProviderConformance(fakeFactory('alias-drift'))
    expect(violations.some((v) => v.check === 'verified-claim')).toBe(true)
  })

  it('flags a wrong channel', async () => {
    const violations = await checkProviderConformance(fakeFactory('wrong-channel'))
    expect(violations.some((v) => v.check === 'channel')).toBe(true)
  })

  it('flags a dropped impersonation actor', async () => {
    const violations = await checkProviderConformance(fakeFactory('drop-actor'))
    expect(violations.some((v) => v.check === 'actor')).toBe(true)
  })

  it('flags a revoke that does not invalidate, unless declared best-effort', async () => {
    const violations = await checkProviderConformance(fakeFactory('revoke-noop'))
    expect(violations.some((v) => v.check === 'revoke-session')).toBe(true)
    await expect(
      assertProviderConformance(fakeFactory('revoke-noop', { bestEffortRevoke: true }))
    ).resolves.toBeUndefined()
  })

  it('flags capability declarations that do not match behavior', async () => {
    for (const breakage of [
      'declare-revoke-all-only',
      'implement-revoke-all-only',
      'unknown-capability',
      'overclaim-capabilities',
    ] as const) {
      const violations = await checkProviderConformance(fakeFactory(breakage))
      expect(
        violations.some((v) => v.check === 'capabilities'),
        breakage
      ).toBe(true)
    }
    const missingScenario = await checkProviderConformance(
      fakeFactory(undefined, { omitImpersonated: true })
    )
    expect(missingScenario.some((v) => v.check === 'capabilities')).toBe(true)
  })

  it('flags a runtime-malformed session instead of trusting its types', async () => {
    const violations = await checkProviderConformance(fakeFactory('malformed-session'))
    expect(violations.some((v) => v.check === 'session-shape')).toBe(true)
  })

  it('throws one error carrying every violation', async () => {
    const error = await assertProviderConformance(fakeFactory('wrong-channel')).catch(
      (caught: unknown) => caught
    )
    expect(error).toBeInstanceOf(ProviderConformanceError)
    if (error instanceof ProviderConformanceError) {
      expect(error.violations.length).toBeGreaterThan(0)
      expect(error.message).toContain('channel')
    }
  })
})

describe('provider conformance kit: server-session capabilities (#54)', () => {
  it('fails when a port declares server-session capabilities without the methods', async () => {
    const built = fakeFactory()
    const subject = built() as ProviderConformanceSubject
    const port = {
      ...subject.port,
      capabilities: new Set<Capability>([
        ...subject.port.capabilities,
        'server-session-create',
        'server-session-list',
        'api-key-verify',
      ]),
    }
    const violations = await checkProviderConformance(() => ({ ...subject, port }))
    expect(
      violations.some(
        (v) =>
          v.message.includes("'server-session-create' but implements no createProviderSession") ||
          v.message.includes("'server-session-list' but implements no listProviderSessions") ||
          v.message.includes("'api-key-verify' but implements no verifyApiKey")
      )
    ).toBe(true)
  })

  it('fails when a port implements server-session methods without declaring them', async () => {
    const built = fakeFactory()
    const subject = built() as ProviderConformanceSubject
    const caps = new Set<Capability>(subject.port.capabilities)
    caps.delete('server-session-create')
    caps.delete('server-session-list')
    const port = {
      ...subject.port,
      capabilities: caps,
      createProviderSession: () => okAsync({ sessionId: 's', token: 't', storedExpiresAt: null }),
      listProviderSessions: () => okAsync([]),
      verifyApiKey: () => okAsync(null),
    }
    const violations = await checkProviderConformance(() => ({ ...subject, port }))
    expect(violations.filter((v) => v.check === 'capabilities').length).toBeGreaterThanOrEqual(3)
  })
})
