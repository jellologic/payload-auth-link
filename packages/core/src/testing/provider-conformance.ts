/**
 * Provider conformance kit (PORT-5): one shared, framework-free suite of
 * checks every `IdentityProviderPort` adapter runs, so session
 * narrowing, verified-claim semantics, actor propagation, channel
 * reporting, declared capabilities, and revoke semantics cannot drift
 * between providers.
 *
 * Test-only surface: exported from `@payload-auth-link/core/testing`,
 * never from the core barrel, and it imports no test framework. A
 * suite supplies a {@link ProviderConformanceFactory} that builds a
 * fresh port plus the scenario drivers (headers + expectations) for
 * each check group; {@link assertProviderConformance} throws one
 * {@link ProviderConformanceError} listing every violation, and
 * {@link checkProviderConformance} returns the violations instead.
 * Sessions are re-validated at runtime as `unknown`: a port that
 * lies in its types still fails.
 */
import { isNonEmptyString, isRecord } from '../guards.js'
import { authMethods, type AuthMethod } from '../ports.js'
import type {
  Capability,
  IdentityProviderPort,
  ProviderSession,
  SessionActor,
  SessionChannel,
} from '../ports.js'

/** One named conformance check a {@link ConformanceViolation} can blame. */
export type ConformanceCheckId =
  | 'session-shape'
  | 'verified-claim'
  | 'assurance'
  | 'actor'
  | 'channel'
  | 'capabilities'
  | 'no-session'
  | 'revoke-session'
  | 'revoke-user-sessions'
  | 'server-session-create'
  | 'server-session-list'
  | 'api-key-verify'

/** One failed conformance assertion: which check, and what was wrong. */
export type ConformanceViolation = {
  readonly check: ConformanceCheckId
  readonly message: string
}

/**
 * Thrown by {@link assertProviderConformance} when a port fails any
 * check. Carries every violation found in the run, not just the first.
 */
export class ProviderConformanceError extends Error {
  readonly violations: readonly ConformanceViolation[]

  constructor(violations: readonly ConformanceViolation[]) {
    super(
      `Provider conformance failed (${String(violations.length)}):\n${violations
        .map((violation) => `- [${violation.check}] ${violation.message}`)
        .join('\n')}`
    )
    this.name = 'ProviderConformanceError'
    this.violations = violations
  }
}

/** What one live-session scenario must narrow to. */
export type ExpectedConformanceSession = {
  readonly providerUserId: string
  /** Expected `identity.email` claim value (and deprecated alias). */
  readonly email: string
  /** Expected claim verification (and deprecated alias). */
  readonly emailVerified: boolean
  readonly channel: SessionChannel
  /** Expected `assurance.methods`; omit to accept any well-formed value. */
  readonly methods?: (readonly AuthMethod[] | 'unknown') | undefined
  /** Expected `assurance.mfa`; omit to accept any well-formed value. */
  readonly mfa?: (boolean | 'unknown') | undefined
  /** Expected actor; defaults to `null` (no impersonation). */
  readonly actor?: SessionActor | null | undefined
  /** Expected `organizationId`; omit to accept any string-or-null. */
  readonly organizationId?: string | null | undefined
  /** Expected `identity.anonymous`; defaults to `false`. */
  readonly anonymous?: boolean | undefined
  /**
   * Expected `identity.phone` claim; omit to require the claim to be
   * well-formed only. Required as evidence when the port declares
   * the `'phone'` capability.
   */
  readonly phone?: { readonly value: string; readonly verified: boolean } | null | undefined
}

/** Scenario drivers for one freshly built port. */
export type ProviderConformanceScenarios = {
  /** A live session with a verified email claim. */
  readonly session: {
    readonly headers: Headers
    readonly expected: ExpectedConformanceSession
  }
  /**
   * A live session whose email claim is unverified: the claim and the
   * deprecated alias must both report `verified: false` (SEC-2).
   */
  readonly unverifiedSession?:
    { readonly headers: Headers; readonly expected: ExpectedConformanceSession } | undefined
  /**
   * A live impersonated session. Required when the port declares
   * `'impersonation'`, and supplying one requires that declaration:
   * declared capabilities must match behavior in both directions.
   */
  readonly impersonatedSession?:
    { readonly headers: Headers; readonly expectedActorProviderUserId: string } | undefined
  /** Headers carrying no session: `getSession` must return ok `null`. */
  readonly noSession?: { readonly headers: Headers } | undefined
  /**
   * Revoke observability. `'invalidates-session'` (the default)
   * requires a revoked session to read back as `null`;
   * `'best-effort'` is the honest declaration for stateless JWT
   * transports whose revocation cannot invalidate the token, and only
   * requires the revoke calls to succeed.
   */
  readonly revoke?: { readonly mode: 'invalidates-session' | 'best-effort' } | undefined
}

/** One fresh port plus its scenario drivers. */
export type ProviderConformanceSubject = {
  readonly port: IdentityProviderPort
  readonly scenarios: ProviderConformanceScenarios
}

/**
 * Builds a fresh {@link ProviderConformanceSubject}. Called once per
 * check group (reads, `revokeSession`, `revokeUserSessions`), so each
 * mutating check starts from a live session.
 */
export type ProviderConformanceFactory = () =>
  ProviderConformanceSubject | Promise<ProviderConformanceSubject>

const allCapabilities: readonly Capability[] = [
  'magic-link',
  'email-otp',
  'passkey',
  'oauth',
  'one-tap',
  'phone',
  'anonymous',
  'mfa',
  'impersonation',
  'revoke-user-sessions',
  'server-session-create',
  'server-session-list',
  'api-key-verify',
]

// The kit accepts exactly the single-sourced method tuple — a private
// copy here could silently drift (B16).
const allAuthMethods: readonly AuthMethod[] = authMethods

const allChannels: readonly SessionChannel[] = ['cookie', 'bearer', 'api-key', 'device']

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : 'non-Error thrown value'
}

type ReadOutcome =
  | { readonly kind: 'session'; readonly session: ProviderSession }
  | { readonly kind: 'none' }
  | { readonly kind: 'failed'; readonly message: string }

async function readSession(
  port: IdentityProviderPort,
  headers: Headers,
  label: string,
  violations: ConformanceViolation[],
  check: ConformanceCheckId
): Promise<ReadOutcome> {
  try {
    const result = await port.getSession(headers)
    if (result.isErr()) {
      violations.push({ check, message: `${label}: getSession failed: ${result.error.message}` })
      return { kind: 'failed', message: result.error.message }
    }
    if (result.value === null) {
      return { kind: 'none' }
    }
    return { kind: 'session', session: result.value }
  } catch (error) {
    violations.push({
      check,
      message: `${label}: getSession threw instead of returning a Result: ${describeError(error)}`,
    })
    return { kind: 'failed', message: describeError(error) }
  }
}

function isReadonlySetLike(value: unknown): value is ReadonlySet<unknown> {
  if (!isRecord(value) || typeof value.has !== 'function') {
    return false
  }
  const iterator: unknown = Reflect.get(value, Symbol.iterator)
  return typeof iterator === 'function'
}

function isClaimShape(value: unknown): boolean {
  return (
    value === null ||
    (isRecord(value) && isNonEmptyString(value.value) && typeof value.verified === 'boolean')
  )
}

/** Runtime-validate one narrowed session against its expectations. */
function checkSession(
  session: ProviderSession,
  expected: ExpectedConformanceSession,
  label: string,
  violations: ConformanceViolation[]
): void {
  const raw: unknown = session
  const fail = (check: ConformanceCheckId, message: string): void => {
    violations.push({ check, message: `${label}: ${message}` })
  }
  if (!isRecord(raw)) {
    fail('session-shape', 'session is not an object')
    return
  }
  if (!isNonEmptyString(raw.sessionId)) {
    fail('session-shape', 'sessionId must be a non-empty string')
  }
  if (!isNonEmptyString(raw.providerUserId)) {
    fail('session-shape', 'providerUserId must be a non-empty string')
  } else if (raw.providerUserId !== expected.providerUserId) {
    fail(
      'session-shape',
      `providerUserId is ${raw.providerUserId}, expected ${expected.providerUserId}`
    )
  }
  if (!(raw.expiresAt instanceof Date) || Number.isNaN(raw.expiresAt.getTime())) {
    fail('session-shape', 'expiresAt must be a valid Date')
  }

  // Identity claims, plus the deprecated aliases kept for one minor:
  // the aliases must be exact copies of the email claim, never drift.
  const identity: unknown = raw.identity
  if (!isRecord(identity)) {
    fail('verified-claim', 'identity must be an object')
  } else {
    if (!isClaimShape(identity.email)) {
      fail('verified-claim', 'identity.email must be null or a {value, verified} claim')
    } else if (identity.email === null) {
      fail('verified-claim', 'identity.email claim must be filled for an email session')
    } else if (isRecord(identity.email)) {
      if (identity.email.value !== expected.email) {
        fail(
          'verified-claim',
          `identity.email.value is ${String(identity.email.value)}, expected ${expected.email}`
        )
      }
      if (identity.email.verified !== expected.emailVerified) {
        fail(
          'verified-claim',
          `identity.email.verified is ${String(identity.email.verified)}, expected ${String(expected.emailVerified)}`
        )
      }
      if (raw.email !== identity.email.value) {
        fail('verified-claim', 'deprecated email alias must equal identity.email.value')
      }
      if (raw.emailVerified !== identity.email.verified) {
        fail('verified-claim', 'deprecated emailVerified alias must equal identity.email.verified')
      }
    }
    if (!isClaimShape(identity.phone)) {
      fail('verified-claim', 'identity.phone must be null or a {value, verified} claim')
    } else if (expected.phone !== undefined) {
      const phone = identity.phone
      if (expected.phone === null) {
        if (phone !== null) {
          fail('verified-claim', 'identity.phone must be null for this scenario')
        }
      } else if (!isRecord(phone)) {
        fail('verified-claim', 'identity.phone claim must be filled for this scenario')
      } else {
        if (phone.value !== expected.phone.value) {
          fail(
            'verified-claim',
            `identity.phone.value is ${String(phone.value)}, expected ${expected.phone.value}`
          )
        }
        if (phone.verified !== expected.phone.verified) {
          fail(
            'verified-claim',
            `identity.phone.verified is ${String(phone.verified)}, expected ${String(expected.phone.verified)}`
          )
        }
      }
    }
    if (typeof identity.anonymous !== 'boolean') {
      fail('verified-claim', 'identity.anonymous must be a boolean')
    } else if (identity.anonymous !== (expected.anonymous ?? false)) {
      fail(
        'verified-claim',
        `identity.anonymous is ${String(identity.anonymous)}, expected ${String(expected.anonymous ?? false)}`
      )
    }
  }

  const assurance: unknown = raw.assurance
  if (!isRecord(assurance)) {
    fail('assurance', 'assurance must be an object')
  } else {
    const { methods, mfa } = assurance
    const methodsOk =
      methods === 'unknown' ||
      (Array.isArray(methods) &&
        methods.every(
          (method) => typeof method === 'string' && allAuthMethods.includes(method as AuthMethod)
        ))
    if (!methodsOk) {
      fail('assurance', "assurance.methods must be 'unknown' or an array of AuthMethod")
    } else if (expected.methods !== undefined) {
      const actual = methods === 'unknown' ? 'unknown' : [...(methods as readonly string[])]
      const wanted = expected.methods === 'unknown' ? 'unknown' : [...expected.methods].sort()
      const comparable = actual === 'unknown' ? actual : [...actual].sort()
      if (JSON.stringify(comparable) !== JSON.stringify(wanted)) {
        fail(
          'assurance',
          `assurance.methods is ${JSON.stringify(actual)}, expected ${JSON.stringify(expected.methods)}`
        )
      }
    }
    if (typeof mfa !== 'boolean' && mfa !== 'unknown') {
      fail('assurance', "assurance.mfa must be a boolean or 'unknown'")
    } else if (expected.mfa !== undefined && mfa !== expected.mfa) {
      fail('assurance', `assurance.mfa is ${String(mfa)}, expected ${String(expected.mfa)}`)
    }
  }

  const actor: unknown = raw.actor
  const expectedActor = expected.actor ?? null
  if (actor !== null && !(isRecord(actor) && isNonEmptyString(actor.providerUserId))) {
    fail('actor', 'actor must be null or {providerUserId: non-empty string}')
  } else if (expectedActor === null) {
    if (actor !== null) {
      fail('actor', 'actor must be null for a plain (non-impersonated) session')
    }
  } else if (!isRecord(actor) || actor.providerUserId !== expectedActor.providerUserId) {
    fail(
      'actor',
      `actor.providerUserId must be ${expectedActor.providerUserId} (impersonation must propagate)`
    )
  }

  if (raw.organizationId !== null && !isNonEmptyString(raw.organizationId)) {
    fail('session-shape', 'organizationId must be null or a non-empty string')
  } else if (
    expected.organizationId !== undefined &&
    raw.organizationId !== expected.organizationId
  ) {
    fail(
      'session-shape',
      `organizationId is ${String(raw.organizationId)}, expected ${String(expected.organizationId)}`
    )
  }

  if (typeof raw.channel !== 'string' || !allChannels.includes(raw.channel as SessionChannel)) {
    fail('channel', `channel must be one of ${allChannels.join(', ')}`)
  } else if (raw.channel !== expected.channel) {
    fail('channel', `channel is ${raw.channel}, expected ${expected.channel}`)
  }
}

function checkCapabilities(
  port: IdentityProviderPort,
  scenarios: ProviderConformanceScenarios,
  session: ProviderSession,
  violations: ConformanceViolation[]
): void {
  const fail = (message: string): void => {
    violations.push({ check: 'capabilities', message })
  }
  const declared: unknown = port.capabilities
  if (!isReadonlySetLike(declared)) {
    fail('capabilities must be a ReadonlySet<Capability>')
    return
  }
  const capabilities = declared
  for (const capability of capabilities) {
    if (typeof capability !== 'string' || !allCapabilities.includes(capability as Capability)) {
      fail(`capabilities contains an unknown capability: ${String(capability)}`)
    }
  }
  // revokeUserSessions exists iff its capability is declared.
  const hasRevokeAll = typeof port.revokeUserSessions === 'function'
  const hasCreate = typeof port.createProviderSession === 'function'
  if (capabilities.has('server-session-create') && !hasCreate) {
    fail("declares 'server-session-create' but implements no createProviderSession")
  }
  if (!capabilities.has('server-session-create') && hasCreate) {
    fail("implements createProviderSession without declaring 'server-session-create'")
  }
  const hasList = typeof port.listProviderSessions === 'function'
  if (capabilities.has('server-session-list') && !hasList) {
    fail("declares 'server-session-list' but implements no listProviderSessions")
  }
  if (!capabilities.has('server-session-list') && hasList) {
    fail("implements listProviderSessions without declaring 'server-session-list'")
  }
  const hasVerifyKey = typeof port.verifyApiKey === 'function'
  if (capabilities.has('api-key-verify') && !hasVerifyKey) {
    fail("declares 'api-key-verify' but implements no verifyApiKey")
  }
  if (!capabilities.has('api-key-verify') && hasVerifyKey) {
    fail("implements verifyApiKey without declaring 'api-key-verify'")
  }
  if (capabilities.has('revoke-user-sessions') && !hasRevokeAll) {
    fail("declares 'revoke-user-sessions' but implements no revokeUserSessions")
  }
  if (!capabilities.has('revoke-user-sessions') && hasRevokeAll) {
    fail("implements revokeUserSessions but does not declare 'revoke-user-sessions'")
  }
  // Impersonation: declaration and observable actor behavior must agree.
  if (capabilities.has('impersonation') && scenarios.impersonatedSession === undefined) {
    fail(
      "declares 'impersonation' but the suite supplied no impersonatedSession scenario to prove it"
    )
  }
  if (!capabilities.has('impersonation') && scenarios.impersonatedSession !== undefined) {
    fail("suite supplied an impersonatedSession scenario but 'impersonation' is not declared")
  }
  // Declared MFA must be observable as a boolean, never 'unknown'.
  if (capabilities.has('mfa') && session.assurance.mfa === 'unknown') {
    fail("declares 'mfa' but assurance.mfa reports 'unknown' for the session scenario")
  }
  // Every remaining capability needs scenario EVIDENCE in both
  // directions: a declaration without a scenario that expects the
  // capability's observable session facts is an unproven claim, and
  // a scenario evidencing a capability the port does not declare is
  // drift. Evidence comes from the expected facts of the live
  // scenarios: auth methods for the sign-in capabilities, a phone
  // claim for 'phone', an anonymous session for 'anonymous'.
  const evidenced = evidencedCapabilities(scenarios)
  for (const capability of evidenceCapabilities) {
    if (capabilities.has(capability) && !evidenced.has(capability)) {
      fail(
        `declares '${capability}' but no scenario evidences it (expected methods/phone/anonymous)`
      )
    }
    if (!capabilities.has(capability) && evidenced.has(capability)) {
      fail(`a scenario evidences '${capability}' but the port does not declare it`)
    }
  }
}

/** Capabilities whose only proof is observable session facts. */
const evidenceCapabilities: readonly Capability[] = [
  'magic-link',
  'email-otp',
  'passkey',
  'oauth',
  'one-tap',
  'phone',
  'anonymous',
]

const methodCapabilities: Partial<Record<AuthMethod, Capability>> = {
  'magic-link': 'magic-link',
  'email-otp': 'email-otp',
  oauth: 'oauth',
  'one-tap': 'one-tap',
  passkey: 'passkey',
  'phone-otp': 'phone',
}

function evidencedCapabilities(scenarios: ProviderConformanceScenarios): ReadonlySet<Capability> {
  const evidenced = new Set<Capability>()
  const expectedSessions = [
    scenarios.session.expected,
    ...(scenarios.unverifiedSession === undefined ? [] : [scenarios.unverifiedSession.expected]),
  ]
  for (const expected of expectedSessions) {
    if (expected.phone !== undefined && expected.phone !== null) {
      evidenced.add('phone')
    }
    if (expected.anonymous === true) {
      evidenced.add('anonymous')
    }
    if (Array.isArray(expected.methods)) {
      for (const method of expected.methods as readonly AuthMethod[]) {
        const capability = methodCapabilities[method]
        if (capability !== undefined) {
          evidenced.add(capability)
        }
        if (method === 'anonymous') {
          evidenced.add('anonymous')
        }
      }
    }
  }
  return evidenced
}

async function checkRevoke(
  factory: ProviderConformanceFactory,
  violations: ConformanceViolation[],
  scope: 'session' | 'user'
): Promise<void> {
  const check: ConformanceCheckId = scope === 'session' ? 'revoke-session' : 'revoke-user-sessions'
  const { port, scenarios } = await factory()
  if (scope === 'user' && !port.capabilities.has('revoke-user-sessions')) {
    return
  }
  const before = await readSession(port, scenarios.session.headers, 'revoke setup', [], check)
  if (before.kind !== 'session') {
    violations.push({ check, message: 'revoke setup: session scenario did not yield a session' })
    return
  }
  try {
    const revoked =
      scope === 'session'
        ? await port.revokeSession(before.session.sessionId)
        : typeof port.revokeUserSessions === 'function'
          ? await port.revokeUserSessions(before.session.providerUserId)
          : null
    if (revoked === null || revoked.isErr()) {
      violations.push({
        check,
        message:
          scope === 'user' && revoked === null
            ? "declares 'revoke-user-sessions' but revokeUserSessions is not callable"
            : `revoke failed: ${revoked !== null && revoked.isErr() ? revoked.error.message : 'unknown'}`,
      })
      return
    }
  } catch (error) {
    violations.push({
      check,
      message: `revoke threw instead of returning a Result: ${describeError(error)}`,
    })
    return
  }
  if ((scenarios.revoke?.mode ?? 'invalidates-session') === 'invalidates-session') {
    const after = await readSession(port, scenarios.session.headers, 'after revoke', [], check)
    if (after.kind !== 'none') {
      violations.push({
        check,
        message:
          scope === 'session'
            ? 'revoked session still reads back as live (or errored) through the same headers'
            : 'session still reads back as live (or errored) after revokeUserSessions',
      })
    }
  }
}

/**
 * Run every conformance check against a provider port factory and
 * return the violations (empty when the port conforms). Never throws
 * for a non-conforming port; a factory that itself throws propagates.
 */
export async function checkProviderConformance(
  factory: ProviderConformanceFactory
): Promise<readonly ConformanceViolation[]> {
  const violations: ConformanceViolation[] = []
  const { port, scenarios } = await factory()

  const live = await readSession(
    port,
    scenarios.session.headers,
    'session scenario',
    violations,
    'session-shape'
  )
  if (live.kind === 'session') {
    checkSession(live.session, scenarios.session.expected, 'session scenario', violations)
    checkCapabilities(port, scenarios, live.session, violations)
  } else if (live.kind === 'none') {
    violations.push({
      check: 'session-shape',
      message: 'session scenario: getSession returned null for a live session',
    })
  }

  if (scenarios.unverifiedSession !== undefined) {
    if (scenarios.unverifiedSession.expected.emailVerified !== false) {
      violations.push({
        check: 'verified-claim',
        message: 'unverifiedSession scenario must expect emailVerified: false',
      })
    }
    const unverified = await readSession(
      port,
      scenarios.unverifiedSession.headers,
      'unverified session scenario',
      violations,
      'verified-claim'
    )
    if (unverified.kind === 'session') {
      checkSession(
        unverified.session,
        scenarios.unverifiedSession.expected,
        'unverified session scenario',
        violations
      )
    } else if (unverified.kind === 'none') {
      violations.push({
        check: 'verified-claim',
        message: 'unverified session scenario: getSession returned null for a live session',
      })
    }
  }

  if (scenarios.impersonatedSession !== undefined) {
    const impersonated = await readSession(
      port,
      scenarios.impersonatedSession.headers,
      'impersonated session scenario',
      violations,
      'actor'
    )
    if (impersonated.kind === 'session') {
      checkSession(
        impersonated.session,
        {
          ...scenarios.session.expected,
          providerUserId: impersonated.session.providerUserId,
          email: impersonated.session.identity.email?.value ?? scenarios.session.expected.email,
          emailVerified:
            impersonated.session.identity.email?.verified ??
            scenarios.session.expected.emailVerified,
          actor: { providerUserId: scenarios.impersonatedSession.expectedActorProviderUserId },
        },
        'impersonated session scenario',
        violations
      )
    } else if (impersonated.kind === 'none') {
      violations.push({
        check: 'actor',
        message: 'impersonated session scenario: getSession returned null for a live session',
      })
    }
  }

  if (scenarios.noSession !== undefined) {
    const none = await readSession(
      port,
      scenarios.noSession.headers,
      'no-session scenario',
      violations,
      'no-session'
    )
    if (none.kind === 'session') {
      violations.push({
        check: 'no-session',
        message: 'no-session scenario: getSession returned a session for anonymous headers',
      })
    }
  }

  await checkRevoke(factory, violations, 'session')
  await checkRevoke(factory, violations, 'user')
  return violations
}

/**
 * Assert that a provider port conforms: resolves when it does and
 * throws {@link ProviderConformanceError} listing every violation
 * otherwise. The one call each adapter's test suite makes.
 */
export async function assertProviderConformance(
  factory: ProviderConformanceFactory
): Promise<void> {
  const violations = await checkProviderConformance(factory)
  if (violations.length > 0) {
    throw new ProviderConformanceError(violations)
  }
}
