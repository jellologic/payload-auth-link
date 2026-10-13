import {
  ChannelNotAdmittedError,
  csrfHeaderName,
  defineUserId,
  InvalidConfigError,
  isNonEmptyString,
  isRecord,
  mfaSatisfied,
  RepositoryError,
  SessionExpiredError,
  UserSuspendedError,
  type LoggerPort,
  type SessionAssurance,
  type SessionChannel,
  type ResolvedSessionActor,
  type SessionInvalidError,
} from '@payload-auth-link/core'
import type { Access, CollectionConfig, PayloadRequest } from 'payload'

export { csrfHeaderName }

/**
 * Loud logging for session verification failures. Storage outages are
 * errors with their cause; dead tokens are warnings. Call before
 * returning `{ user: null }` / 401 so every denial is traceable.
 */
export function logVerifyFailure(
  logger: LoggerPort,
  scope: string,
  error:
    | SessionInvalidError
    | SessionExpiredError
    | ChannelNotAdmittedError
    | UserSuspendedError
    | RepositoryError
): void {
  if (error instanceof RepositoryError) {
    logger.error(`${scope} verification failed: storage error`, { cause: error.cause ?? error })
    return
  }
  if (error instanceof SessionExpiredError) {
    logger.warn(`${scope} verification failed: session expired`)
    return
  }
  if (error instanceof ChannelNotAdmittedError) {
    logger.warn(`${scope} verification failed: channel not admitted`, {
      channel: error.channel,
    })
    return
  }
  if (error instanceof UserSuspendedError) {
    logger.warn(`${scope} verification failed: user suspended`, {
      suspendedUntil: error.suspendedUntil.toISOString(),
    })
    return
  }
  // Plain "invalid session" covers every anonymous request (no
  // cookie, no session) — warning here would spam the log on every
  // logged-out page load. Actionable variants above keep their
  // warning, and a session-shaped cookie that resolves to nothing is
  // warned where it is detected (session.ts, with the stale-config
  // message); this residue is trace noise, so: debug.
  logger.debug(`${scope} verification failed: invalid session`)
}

/** Strict same-origin comparison against `baseUrl`. Never throws. */
export function isSameOrigin(value: string, baseUrl: string): boolean {
  let candidate: URL
  let base: URL
  try {
    candidate = new URL(value)
    base = new URL(baseUrl)
  } catch {
    return false
  }
  return candidate.origin === base.origin
}

/**
 * CSRF proof for state-changing endpoints: a matching `Origin` header or the
 * custom header. Requests with neither (plain cross-site forms, blind curl)
 * fail closed.
 */
export function passesCsrf(headers: Headers, baseUrl: string): boolean {
  if (headers.get(csrfHeaderName) === '1') {
    return true
  }
  const origin = headers.get('origin')
  if (!origin) {
    return false
  }
  return isSameOrigin(origin, baseUrl)
}

/**
 * Channel-aware CSRF proof (CAP-13b). Cookie sessions are ambient
 * credentials — a cross-site page can ride them — so they always
 * need {@link passesCsrf}. A presented `Authorization: Bearer`
 * token is NOT ambient (no browser attaches it cross-site), so when
 * the deployment explicitly admits the `bearer` channel, the origin
 * check is skipped for bearer-presented requests ONLY. Anything
 * else (no header, bearer not admitted) keeps the cookie rules.
 * Note this only decides CSRF: whether the bearer session itself is
 * admitted is the session service's channel gate, which still runs.
 */
export function passesCsrfForChannel(
  headers: Headers,
  baseUrl: string,
  admitChannels: readonly SessionChannel[]
): boolean {
  if (admitChannels.includes('bearer')) {
    const authorization = headers.get('authorization')
    if (authorization !== null && /^bearer\s+\S/i.test(authorization.trim())) {
      return true
    }
  }
  return passesCsrf(headers, baseUrl)
}

/**
 * JSON envelope for endpoint responses. Session state must never sit in
 * any cache (browser, proxy, or framework): every response carries
 * `no-store`, including errors — a cached 401 would pin a signed-out
 * user, a cached 200 a signed-in one.
 */
export function jsonResponse(data: unknown, status: number): Response {
  const response = Response.json(data, { status })
  response.headers.set('Cache-Control', 'no-store')
  return response
}

/** 401 envelope; the detail never leaks which check failed. */
export function unauthorized(detail = 'authentication required'): Response {
  return jsonResponse({ error: detail }, 401)
}

/** 403 envelope for authenticated-but-denied requests. */
export function forbidden(detail = 'forbidden'): Response {
  return jsonResponse({ error: detail }, 403)
}

/**
 * Server-side impersonation state of a Payload request. This is the
 * AUTHORIZATION view, deliberately separate from the client wire
 * parser (`parseSessionUser`): it reads only the `actor` field the
 * auth strategy projects onto `req.user`, requires no wire-valid
 * identity fields around it, and is FAIL-CLOSED — a present,
 * non-null `actor` that cannot be parsed is `malformed-actor`,
 * which every deny/audit path treats as impersonating. A parse
 * failure can never launder an impersonated request into a plain
 * one.
 */
export type ImpersonationState =
  | { readonly kind: 'none' }
  | { readonly kind: 'actor'; readonly actor: ResolvedSessionActor }
  | { readonly kind: 'malformed-actor' }

function parseServerActor(raw: unknown): ResolvedSessionActor | null {
  if (!isRecord(raw)) {
    return null
  }
  // Unknown extra keys are ignored (forward compatibility), known
  // keys stay strict. The legacy `{ providerUserId }` form (no
  // `kind`) normalizes to `provider-only`, as on the wire.
  if (raw.kind === undefined) {
    return isNonEmptyString(raw.providerUserId)
      ? { kind: 'provider-only', providerUserId: raw.providerUserId }
      : null
  }
  if (raw.kind === 'provider-only') {
    return isNonEmptyString(raw.providerUserId)
      ? { kind: 'provider-only', providerUserId: raw.providerUserId }
      : null
  }
  if (raw.kind === 'payload-user') {
    const userId =
      isNonEmptyString(raw.userId) ||
      (typeof raw.userId === 'number' && Number.isFinite(raw.userId))
        ? String(raw.userId)
        : ''
    return isNonEmptyString(raw.providerUserId) && userId !== ''
      ? {
          kind: 'payload-user',
          providerUserId: raw.providerUserId,
          userId: defineUserId(userId),
        }
      : null
  }
  return null
}

/** Fail-closed server extraction; see {@link ImpersonationState}. */
export function impersonationStateFromRequest(req: PayloadRequest): ImpersonationState {
  const user: unknown = req.user
  if (!isRecord(user)) {
    return { kind: 'none' }
  }
  const raw: unknown = user.actor
  if (raw === undefined || raw === null) {
    return { kind: 'none' }
  }
  const actor = parseServerActor(raw)
  return actor === null ? { kind: 'malformed-actor' } : { kind: 'actor', actor }
}

/**
 * Whether this request is impersonated, fail-closed: a well-formed
 * actor OR a present-but-malformed one. Authorization denies must
 * use this (or {@link impersonationStateFromRequest}), never a
 * null-check on {@link impersonationActorFromRequest}.
 */
export function isImpersonating(req: PayloadRequest): boolean {
  return impersonationStateFromRequest(req).kind !== 'none'
}

/**
 * The impersonating operator behind a Payload request, or `null`
 * when there is none — or none that can be honestly named. For
 * ATTRIBUTION (audit fields, display) only: a malformed actor
 * yields `null` here yet still denies via {@link isImpersonating},
 * so never gate access on this function's nullness.
 */
export function impersonationActorFromRequest(req: PayloadRequest): ResolvedSessionActor | null {
  const state = impersonationStateFromRequest(req)
  return state.kind === 'actor' ? state.actor : null
}

/** Collection operations {@link denyWhileImpersonating} can guard. */
export type ImpersonationOperation =
  'admin' | 'create' | 'delete' | 'read' | 'readVersions' | 'unlock' | 'update'

const impersonationOperations: readonly ImpersonationOperation[] = [
  'admin',
  'create',
  'delete',
  'read',
  'readVersions',
  'unlock',
  'update',
]

/**
 * Default operations denied while impersonating (CAP-8b / D5):
 * admin-panel access and every write — which includes role changes,
 * since roles change through user updates — while reads stay allowed
 * so an operator can see what the user sees. The plugin applies the
 * admin + roles-field half of this default to the users collection
 * itself; `denyWhileImpersonating` extends it to your collections.
 */
export const defaultDeniedWhileImpersonating: readonly ImpersonationOperation[] = [
  'admin',
  'create',
  'delete',
  'unlock',
  'update',
]

/** The collection `access` map {@link denyWhileImpersonating} returns. */
export type DenyWhileImpersonatingAccess = NonNullable<CollectionConfig['access']>

/**
 * Build a collection `access` map that denies the given operations
 * while an operator is impersonating the request's user (CAP-8b,
 * decision D5: configurable, default read-mostly). Non-denied
 * operations — and every operation for a non-impersonated request —
 * return `true`, so compose with your own rules instead of replacing
 * them: wrap the slot you need (`access.update` below) or call
 * {@link impersonationActorFromRequest} inside your access function.
 * This helper is a deny layer, never a grant.
 *
 * ```ts
 * const impersonation = denyWhileImpersonating()
 * access: {
 *   admin: impersonation.admin,
 *   update: ({ req }) =>
 *     !isImpersonating(req) && myOwnUpdateRule(req),
 * }
 * ```
 *
 * Payload evaluates access per operation slot, so there is no
 * single-function form: the map is the honest shape. Unknown
 * operation names (from JS callers) fail fast with
 * `InvalidConfigError` instead of silently guarding nothing.
 */
export function denyWhileImpersonating(
  operations: readonly ImpersonationOperation[] = defaultDeniedWhileImpersonating
): DenyWhileImpersonatingAccess {
  for (const operation of operations) {
    if (!impersonationOperations.includes(operation)) {
      throw new InvalidConfigError(
        `denyWhileImpersonating got an unknown operation ${JSON.stringify(operation)}; expected one of ${impersonationOperations.join(', ')}`
      )
    }
  }
  const denied = new Set<ImpersonationOperation>(operations)
  const guard = (operation: ImpersonationOperation): Access => {
    if (!denied.has(operation)) {
      return () => true
    }
    return ({ req }) => !isImpersonating(req)
  }
  return {
    admin: ({ req }) => (denied.has('admin') ? !isImpersonating(req) : true),
    create: guard('create'),
    delete: guard('delete'),
    read: guard('read'),
    readVersions: guard('readVersions'),
    unlock: guard('unlock'),
    update: guard('update'),
  }
}

/**
 * Server-side MFA state of a Payload request (CAP-6), read from the
 * `assurance` fact the auth strategy projects onto `req.user`.
 * FAIL-CLOSED like the impersonation extraction: absent, `'unknown'`,
 * or malformed assurance is "not satisfied" — only the literal
 * `mfa: true` passes. Never route this through the client wire
 * parser; this reads the server-projected user only.
 */
export function sessionMfaSatisfied(req: PayloadRequest): boolean {
  const user: unknown = req.user
  if (!isRecord(user) || !isRecord(user.assurance)) {
    return false
  }
  const assurance: SessionAssurance = {
    methods: 'unknown',
    mfa: user.assurance.mfa === true ? true : 'unknown',
  }
  return mfaSatisfied(assurance)
}

/**
 * Build a collection `access` map that denies the given operations
 * unless the request's session carries MFA proof (CAP-6). The
 * companion to {@link denyWhileImpersonating} and composed the same
 * way — a deny layer, never a grant. The default denies the admin
 * panel and every write; the plugin's `policies.requireMfaForRoles`
 * covers role-gated surfaces by withholding the roles themselves,
 * while this helper guards collections whose sensitivity is not
 * role-shaped. Unknown operation names fail fast.
 */
export function denyWithoutMfa(
  operations: readonly ImpersonationOperation[] = defaultDeniedWhileImpersonating
): DenyWhileImpersonatingAccess {
  for (const operation of operations) {
    if (!impersonationOperations.includes(operation)) {
      throw new InvalidConfigError(
        `denyWithoutMfa got an unknown operation ${JSON.stringify(operation)}; expected one of ${impersonationOperations.join(', ')}`
      )
    }
  }
  const denied = new Set<ImpersonationOperation>(operations)
  const guard = (operation: ImpersonationOperation): Access => {
    if (!denied.has(operation)) {
      return () => true
    }
    return ({ req }) => sessionMfaSatisfied(req)
  }
  return {
    admin: ({ req }) => (denied.has('admin') ? sessionMfaSatisfied(req) : true),
    create: guard('create'),
    delete: guard('delete'),
    read: guard('read'),
    readVersions: guard('readVersions'),
    unlock: guard('unlock'),
    update: guard('update'),
  }
}
