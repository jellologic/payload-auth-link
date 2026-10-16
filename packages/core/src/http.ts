import { z } from 'zod'
import { parseEmail } from './email.js'
import { InvalidConfigError } from './errors.js'
import { isNonEmptyString, isRecord } from './guards.js'
import {
  authMethods,
  defineUserId,
  type ResolvedSessionActor,
  type SessionAssurance,
} from './ports.js'
import { parseRole } from './roles.js'

/**
 * Custom CSRF header. A cross-site page cannot set it without a preflight,
 * so its presence proves a same-origin (or deliberate non-browser) caller.
 * UI adapters always send it with the value `1` on state-changing requests.
 */
export const csrfHeaderName = 'x-auth-link-csrf'

/**
 * Default plugin session endpoint path. Payload serves custom endpoints
 * under `/api`; builders who customize `routes.api` override the endpoint
 * in the UI adapters instead of this constant.
 */
export const defaultSessionEndpointPath = '/api/auth-link/session'

/**
 * Injectible `fetch` shape. UI adapters default to the global `fetch`;
 * tests inject stubs. Same signature as `fetch` restricted to string URLs.
 */
export type HttpFetch = (input: string, init?: RequestInit) => Promise<Response>

/**
 * Validate a configured origin. Returns it unchanged when it is an
 * absolute http(s) URL; throws `InvalidConfigError` otherwise. Call at
 * wiring time so a malformed base URL fails the build, never a request
 * (where `new URL` would throw a bare `TypeError` instead).
 */
export function normalizeBaseUrl(baseUrl: string): string {
  let parsed: URL
  try {
    parsed = new URL(baseUrl)
  } catch {
    throw new InvalidConfigError(
      `baseUrl must be an absolute http(s) URL, got ${JSON.stringify(baseUrl)}`
    )
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new InvalidConfigError(
      `baseUrl must be an absolute http(s) URL, got ${JSON.stringify(baseUrl)}`
    )
  }
  return baseUrl
}

/** Origin resolution: configured base URL plus the dev-only host fallback. */
export type OriginResolutionInput = {
  /** Validated configured origin; wins whenever set. */
  readonly baseUrl?: string | undefined
  /** Request headers, for the host fallback only. */
  readonly headers: Headers
  /**
   * Whether the request-host fallback is allowed. Host headers are
   * client-spoofable, so production session reads (which forward
   * cookies to the resolved origin) must pass `false`; local
   * development passes `true`.
   */
  readonly allowHostFallback: boolean
  /**
   * Honor `X-Forwarded-Host` / `X-Forwarded-Proto` in the host
   * fallback. Default `false`: only the direct `Host` header is read
   * and the scheme is `http`. Set it only behind a proxy that
   * overwrites those headers — otherwise any client sets them.
   */
  readonly trustProxy?: boolean | undefined
  /**
   * Hostnames (no port; IPv6 in brackets, e.g. `[::1]`) the host
   * fallback may resolve to. When set, any other host throws
   * `InvalidConfigError`. Omitted: any syntactically valid host.
   */
  readonly allowedHosts?: readonly string[] | undefined
}

/** A bare `host[:port]`: DNS name / IPv4, or a bracketed IPv6 literal. */
const bareHostPattern = /^(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i

/** First entry of a possibly comma-joined proxy header. */
function firstHeaderValue(value: string | null): string | null {
  if (value === null) {
    return null
  }
  const first = value.split(',')[0]?.trim()
  return first === undefined || first === '' ? null : first
}

/**
 * Single origin resolver behind every server-side session read
 * (`@payload-auth-link/web` verifier, Auth.js engine). The configured
 * base URL wins; without it, the request host is used only when
 * `allowHostFallback` is set. The fallback reads `X-Forwarded-*` only
 * under `trustProxy`, accepts only the `http`/`https` schemes, rejects
 * hosts that are not a bare `host[:port]`, and enforces `allowedHosts`
 * when given. Throws `InvalidConfigError` when no acceptable origin can
 * be resolved — fail loud rather than fetching a nonsense (or
 * attacker-chosen) URL.
 */
export function resolveOrigin(input: OriginResolutionInput): string {
  if (input.baseUrl !== undefined) {
    return normalizeBaseUrl(input.baseUrl)
  }
  if (!input.allowHostFallback) {
    throw new InvalidConfigError(
      'cannot resolve origin: no baseUrl configured and the request-host fallback is disabled'
    )
  }
  const trustProxy = input.trustProxy === true
  const forwardedHost = trustProxy ? firstHeaderValue(input.headers.get('x-forwarded-host')) : null
  const host = forwardedHost ?? input.headers.get('host')
  if (!host) {
    throw new InvalidConfigError('cannot resolve origin: no host header and no baseUrl')
  }
  const forwardedProto = trustProxy
    ? firstHeaderValue(input.headers.get('x-forwarded-proto'))
    : null
  const proto = (forwardedProto ?? 'http').toLowerCase()
  if (proto !== 'http' && proto !== 'https') {
    throw new InvalidConfigError(
      `cannot resolve origin: request scheme ${JSON.stringify(proto)} is not http or https`
    )
  }
  // Only a bare `host[:port]` (IPv6 in brackets): no credentials,
  // path, query, or fragment can ride along into the URL.
  let parsed: URL | undefined
  if (bareHostPattern.test(host)) {
    try {
      parsed = new URL(`${proto}://${host}`)
    } catch {
      parsed = undefined
    }
  }
  if (parsed === undefined) {
    throw new InvalidConfigError(`cannot resolve origin: invalid host ${JSON.stringify(host)}`)
  }
  if (input.allowedHosts !== undefined) {
    const hostname = parsed.hostname.toLowerCase()
    const allowed = input.allowedHosts.some((entry) => entry.toLowerCase() === hostname)
    if (!allowed) {
      throw new InvalidConfigError(
        `cannot resolve origin: host ${JSON.stringify(parsed.hostname)} is not in the allowed host list`
      )
    }
  }
  return parsed.origin
}

/**
 * The session user: what the plugin's session endpoint returns inside its
 * `{ user }` envelope, and what the UI adapters hydrate from. Plain JSON —
 * roles are the wire form of `Role`, re-validated on parse.
 *
 * The PORT-4 fields are additive and optional, so payloads from older
 * servers (without them) still parse, and older clients ignore them.
 * Producers include a field only when it is known: `actor` only while
 * an operator impersonates the user, `organizationId` only when the
 * provider reports an active tenant. `assurance` is the exception that
 * proves the rule — when the provider reported it, it serializes even
 * when its values are `'unknown'`, because "the provider cannot tell"
 * is itself a fact. Consumers must treat absent or `'unknown'`
 * assurance as not satisfied (R3 fail-closed): it never proves a
 * method or MFA.
 */
export type SessionUser = {
  readonly id: string
  readonly collection: string
  readonly email: string
  readonly roles: readonly string[]
  /** How the session was proven, when the provider reported it. */
  readonly assurance?: SessionAssurance | undefined
  /**
   * The impersonating operator, present only while impersonating,
   * resolved against Payload users when linked (CAP-8b): the
   * `kind: 'payload-user'` form also carries the operator's Payload
   * user id; `kind: 'provider-only'` means no linked Payload user.
   */
  readonly actor?: ResolvedSessionActor | undefined
  /** Provider-native active tenant, when one is active. */
  readonly organizationId?: string | undefined
  /**
   * Present (`true`) only when a `requireMfaForRoles` policy (CAP-6)
   * withheld one or more of the user's stored roles from `roles`
   * because this session lacks MFA proof — the UI's signal to prompt
   * for a step-up sign-in instead of a flat "forbidden".
   */
  readonly mfaRequired?: true | undefined
}

// Derived from the `authMethods` tuple in ports.ts (single source,
// B16): the wire enum and the `AuthMethod` union cannot drift apart.
const authMethodSchema = z.enum(authMethods)

// Non-strict on purpose (forward compatibility): a newer server may
// add keys inside these optional facts, and an older client must keep
// reading the session instead of nuking the whole user. Unknown keys
// are stripped; known keys stay strictly typed.
const sessionAssuranceSchema = z.object({
  methods: z.union([z.array(authMethodSchema), z.literal('unknown')]),
  mfa: z.union([z.boolean(), z.literal('unknown')]),
})

const resolvedSessionActorSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('payload-user'),
    providerUserId: z.string().min(1),
    userId: z.string().min(1),
  }),
  z.object({ kind: z.literal('provider-only'), providerUserId: z.string().min(1) }),
])

/**
 * Pre-CAP-8b wire form (`{ providerUserId }` with no resolution):
 * accepted and normalized to `provider-only`, which is exactly what
 * it always meant — an operator known only by provider id.
 */
const legacySessionActorSchema = z.object({ providerUserId: z.string().min(1) })

/**
 * Why {@link parseSessionUser} degraded an optional wire field instead
 * of trusting it (B20). Reported through
 * {@link ParseSessionUserOptions.onDegrade} so a producer/consumer
 * version skew is observable in logs instead of silent: an unknown
 * `AuthMethod` from a newer server lands here as
 * `'assurance-malformed'`, never as a mysteriously absent session.
 */
export type SessionUserDegradeReason =
  'assurance-malformed' | 'actor-malformed' | 'organization-malformed'

/** Options for {@link parseSessionUser}. */
export type ParseSessionUserOptions = {
  /**
   * Called once per degraded optional field. Intended for a
   * `LoggerPort.warn` at the composition root; omitted by default,
   * which preserves the historical silent fail-closed behavior.
   */
  readonly onDegrade?: ((reason: SessionUserDegradeReason) => void) | undefined
}

/**
 * Narrow unknown JSON to a `SessionUser`. This is the CLIENT wire
 * parser: core identity fields (`id`, `collection`, `email`,
 * `roles`) stay strict and fail closed (`null`) on any deviation,
 * because a partial identity is never a session.
 *
 * The optional PORT-4 fields degrade instead of nuking the user:
 * unknown keys inside `assurance`/`actor` are ignored (forward
 * compatibility with newer servers), and a present-but-malformed
 * optional degrades fail-closed-for-policy — `assurance` to
 * `'unknown'`/`'unknown'` (which never satisfies a policy requiring
 * proof), `actor`/`organizationId` to absent. Dropping a malformed
 * client-side actor marker is safe ONLY because server-side
 * authorization and audit never route through this parser: the
 * plugin extracts the actor from `req.user` with its own fail-closed
 * server extraction (a malformed actor there still denies). The
 * explicit `null` a producer may carry for "no actor / no tenant"
 * normalizes to absent; `null` assurance degrades to `'unknown'`.
 */
export function parseSessionUser(
  value: unknown,
  options?: ParseSessionUserOptions
): SessionUser | null {
  const onDegrade = options?.onDegrade
  if (!isRecord(value)) {
    return null
  }
  if (!isNonEmptyString(value.id) || !isNonEmptyString(value.collection)) {
    return null
  }
  const email = parseEmail(value.email)
  if (email.isErr()) {
    return null
  }
  if (!Array.isArray(value.roles)) {
    return null
  }
  const roles: string[] = []
  for (const role of value.roles) {
    const parsed = parseRole(role)
    if (parsed.isErr()) {
      return null
    }
    roles.push(parsed.value)
  }
  let assurance: SessionAssurance | undefined
  if (value.assurance !== undefined) {
    const parsed = sessionAssuranceSchema.safeParse(value.assurance)
    if (parsed.success) {
      assurance = {
        methods: parsed.data.methods === 'unknown' ? 'unknown' : [...parsed.data.methods],
        mfa: parsed.data.mfa,
      }
    } else {
      assurance = { methods: 'unknown', mfa: 'unknown' }
      onDegrade?.('assurance-malformed')
    }
  }
  let actor: ResolvedSessionActor | undefined
  if (value.actor !== undefined && value.actor !== null) {
    const parsed = resolvedSessionActorSchema.safeParse(value.actor)
    if (parsed.success) {
      actor =
        parsed.data.kind === 'payload-user'
          ? {
              kind: 'payload-user',
              providerUserId: parsed.data.providerUserId,
              userId: defineUserId(parsed.data.userId),
            }
          : { kind: 'provider-only', providerUserId: parsed.data.providerUserId }
    } else {
      const legacy = legacySessionActorSchema.safeParse(value.actor)
      if (legacy.success) {
        actor = { kind: 'provider-only', providerUserId: legacy.data.providerUserId }
      } else {
        onDegrade?.('actor-malformed')
      }
      // Malformed actor degrades to absent on the wire; server authz
      // uses its own fail-closed extraction (see the TSDoc above).
    }
  }
  let organizationId: string | undefined
  if (value.organizationId !== undefined && value.organizationId !== null) {
    if (isNonEmptyString(value.organizationId)) {
      organizationId = value.organizationId
    } else {
      onDegrade?.('organization-malformed')
    }
  }
  return {
    id: value.id,
    collection: value.collection,
    email: email.value,
    roles,
    ...(assurance === undefined ? {} : { assurance }),
    ...(actor === undefined ? {} : { actor }),
    ...(organizationId === undefined ? {} : { organizationId }),
    // Only the literal `true` survives: anything else is not a
    // step-up signal (absent and malformed alike degrade to absent).
    ...(value.mfaRequired === true ? { mfaRequired: true as const } : {}),
  }
}

/**
 * The guest principal as it travels on the wire (CAP-10): the session
 * endpoint answers `{ user: null, guest }` for a live anonymous
 * provider session. A guest has NO Payload user, roles, or access —
 * `id` is only a stable key for anonymous app state.
 */
export type SessionGuest = {
  readonly id: string
  readonly providerId: string
  /** ISO instant the underlying provider session expires. */
  readonly expiresAt: string
}

/** Narrow unknown JSON to a `SessionGuest`; `null` on any deviation. */
export function parseSessionGuest(value: unknown): SessionGuest | null {
  if (!isRecord(value)) {
    return null
  }
  if (
    !isNonEmptyString(value.id) ||
    !isNonEmptyString(value.providerId) ||
    !isNonEmptyString(value.expiresAt)
  ) {
    return null
  }
  return { id: value.id, providerId: value.providerId, expiresAt: value.expiresAt }
}

/**
 * Parse a session-endpoint `Response` through its `{ guest }`
 * envelope (CAP-10). Fails closed exactly like
 * {@link parseSessionResponse}; note a guest body parses to `null`
 * there (its `user` is `null`), so user-only consumers stay correct
 * without knowing guests exist.
 */
export async function parseGuestResponse(
  response: Pick<Response, 'ok' | 'json'>
): Promise<SessionGuest | null> {
  if (!response.ok) {
    return null
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return null
  }
  if (!isRecord(body) || body.user !== null) {
    return null
  }
  return parseSessionGuest(body.guest)
}

/**
 * Parse a session-endpoint `Response` through its `{ user }` envelope.
 * Fails closed (`null`) on non-2xx statuses, unreadable JSON, non-record
 * bodies, and malformed users — the single envelope parser shared by
 * the client reader (`react`) and the server verifier (`web`).
 */
export async function parseSessionResponse(
  response: Pick<Response, 'ok' | 'json'>
): Promise<SessionUser | null> {
  if (!response.ok) {
    return null
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    return null
  }
  if (!isRecord(body)) {
    return null
  }
  return parseSessionUser(body.user)
}
