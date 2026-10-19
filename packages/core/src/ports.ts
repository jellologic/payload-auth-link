import { err, ok, ResultAsync } from 'neverthrow'
import { z } from 'zod'
import type { Email } from './email.js'
import type { IdentityEventHandler } from './events.js'
import {
  ChannelNotAdmittedError,
  InvalidProviderIdError,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnknownProviderError,
  UserSuspendedError,
  UnsupportedCapabilityError,
  UserExistsError,
} from './errors.js'
import type { PhoneNumber } from './phone.js'
import type { Role } from './roles.js'

// ---------------------------------------------------------------------------
// Branded identities
// ---------------------------------------------------------------------------

/** Payload document id of a user. */
export type UserId = string & { readonly __brand: 'UserId' }

/** Opaque session id. */
export type SessionId = string & { readonly __brand: 'SessionId' }

/** Provider-id boundary schema: lowercase slug, branded `ProviderId`. */
export const providerIdSchema = z
  .string()
  .min(1, 'provider id must not be empty')
  .max(64, 'provider id must be at most 64 characters')
  .regex(/^[a-z0-9][a-z0-9_-]*$/, 'provider id must be lowercase alphanumeric with - or _')
  .brand<'ProviderId'>()

/**
 * Identity-provider id (`better-auth`, `authjs`, custom …).
 * Well-known ids come from {@link wellKnownProviderIds}; custom adapters
 * brand their own via {@link defineProviderId} (fail-fast on invalid input).
 */
export type ProviderId = z.output<typeof providerIdSchema>

/**
 * Brand a provider id. Throws {@link InvalidProviderIdError} on invalid
 * input: an invalid literal is a programmer error at wiring time, so failing
 * fast and loudly is correct — never a silent fallback.
 */
export function defineProviderId(id: string): ProviderId {
  const parsed = providerIdSchema.safeParse(id)
  if (!parsed.success) {
    throw new InvalidProviderIdError(parsed.error.issues.map((issue) => issue.message).join('; '))
  }
  return parsed.data
}

/**
 * Brand a Payload document id. Throws on empty input: ids come from storage,
 * so an empty id is a bug at the adapter boundary, not an expected failure.
 */
export function defineUserId(id: string): UserId {
  if (id === '') {
    throw new Error('User id must not be empty')
  }
  return id as UserId
}

/**
 * Brand an opaque session id. Throws on empty input, like
 * {@link defineUserId}.
 */
export function defineSessionId(id: string): SessionId {
  if (id === '') {
    throw new Error('Session id must not be empty')
  }
  return id as SessionId
}

/**
 * Reserved provider ids. `workos`/`clerk` are deferred post-v1 but their ids
 * are reserved here so the registry shape never changes under adapters.
 */
export const wellKnownProviderIds = {
  betterAuth: defineProviderId('better-auth'),
  authjs: defineProviderId('authjs'),
  workos: defineProviderId('workos'),
  clerk: defineProviderId('clerk'),
} as const

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** A provider-side identity, independent of any user document. */
export type ProviderIdentityRef = {
  readonly providerId: ProviderId
  readonly providerUserId: string
}

/** A provider identity linked to a user document. */
export type LinkedIdentity = ProviderIdentityRef & {
  readonly email: Email
  readonly linkedAt: Date
}

/** The canonical user: one Payload document, N linked identities. */
export type UserRecord = {
  readonly id: UserId
  readonly email: Email
  readonly roles: readonly Role[]
  readonly identities: readonly LinkedIdentity[]
  readonly createdAt: Date
  readonly updatedAt: Date
  /**
   * Verified E.164 phone on file (CAP-9), when the user store carries
   * one. Optional/additive: repositories without a phone field omit
   * it. This is the value `findByPhone` resolves on; it is written
   * only from a verified provider claim or by an operator.
   */
  readonly phone?: PhoneNumber | null | undefined
  /**
   * Suspension expiry (CAP-7): while in the future, session
   * verification refuses this user for every provider and strategy.
   * `null`/absent means not suspended; a past instant means lapsed.
   */
  readonly suspendedUntil?: Date | null | undefined
  /** Operator-facing suspension reason (CAP-7). Never sent to clients. */
  readonly suspendReason?: string | null | undefined
}

/** Registration input: every provisioned user starts with roles. */
export type NewUser = {
  readonly email: Email
  readonly roles: readonly Role[]
  readonly identity?: ProviderIdentityRef | undefined
  /** Verified phone to store at provisioning time (CAP-9). */
  readonly phone?: PhoneNumber | undefined
}

/**
 * A verified plugin-level session: provider-agnostic, role-free.
 *
 * The PORT-4 facts (`assurance`, `actor`, `organizationId`) are
 * optional and additive: a `SessionPort` implementation that cannot
 * know them omits them, and consumers must treat an absent fact as
 * unknown — never as satisfied (R3 fail-closed: `'unknown'`
 * assurance does not satisfy a policy requiring proof). When a
 * provider does report `assurance`, it is carried even when its
 * values are `'unknown'`, so "the provider cannot tell" stays
 * distinguishable from "nobody asked". `actor` is present only
 * while an operator impersonates the user, and `organizationId`
 * only when the provider reports an active tenant.
 */
export type Session = {
  readonly id: SessionId
  readonly userId: UserId
  readonly providerId: ProviderId
  readonly expiresAt: Date
  /** How the session was proven, when the provider reported it. */
  readonly assurance?: SessionAssurance | undefined
  /**
   * The impersonating operator, present only while impersonating,
   * resolved against Payload users (CAP-8b {@link ResolvedSessionActor}).
   */
  readonly actor?: ResolvedSessionActor | undefined
  /** Provider-native active tenant, when one is active. */
  readonly organizationId?: string | undefined
}

/**
 * One identifier claim from the provider plus whether the provider
 * verified it. The claim is the linking authority (SEC-2): only a
 * `verified` claim may link or provision a Payload user.
 */
export type VerifiedClaim<T> = {
  readonly value: T
  readonly verified: boolean
}

/**
 * How the user proved their identity for this session. Providers that
 * record no per-session method report `'unknown'` on
 * {@link SessionAssurance} instead of guessing (Phase 0 spike S4:
 * Better Auth has no per-session method; its per-user
 * `lastLoginMethod` must never back per-session assurance).
 */
/**
 * Every {@link AuthMethod} value, single-sourced: the union below and
 * the wire `z.enum` in `http.ts` both derive from this tuple, so the
 * two can never drift apart silently (B16).
 */
export const authMethods = [
  'password',
  'magic-link',
  'email-otp',
  'oauth',
  'one-tap',
  'passkey',
  'phone-otp',
  'anonymous',
  // Server-session provenance (#54): the engine records HOW a session
  // came into being, and the assurance projection reads that
  // per-session fact. A mint ran no challenge; `server-step-up` is
  // set only when the server vouches a second factor it verified
  // itself; `two-factor` is reserved for flows that record one.
  'server-mint',
  'server-step-up',
  'two-factor',
] as const

export type AuthMethod = (typeof authMethods)[number]

/** The identity claims a provider session carries (PORT-1). */
export type ProviderIdentityClaims = {
  /** The email claim, or `null` when the session has no email identity. */
  readonly email: VerifiedClaim<Email> | null
  /** The E.164 phone claim, or `null`. Filled by CAP-9 adapters. */
  readonly phone: VerifiedClaim<PhoneNumber> | null
  /** True for an anonymous/guest identity, which never links (D3). */
  readonly anonymous: boolean
}

/**
 * How strongly this session was proven. `'unknown'` is a first-class
 * value, never a guess: policies requiring proof treat it as absent.
 * On Better Auth `mfa` reflects enrollment (`user.twoFactorEnabled`,
 * spike S3), not per-session proof, which BA 1.7.7 cannot report.
 */
export type SessionAssurance = {
  readonly methods: readonly AuthMethod[] | 'unknown'
  readonly mfa: boolean | 'unknown'
}

/** The operator acting as this user while impersonating (CAP-8). */
export type SessionActor = {
  readonly providerUserId: string
}

/**
 * A {@link SessionActor} resolved against Payload users (CAP-8b), as
 * carried on the plugin-level {@link Session} and the `SessionUser`
 * wire shape. Discriminated so an unresolved operator can never be
 * mistaken for a Payload user:
 *
 * - `payload-user`: the operator's provider identity is linked to a
 *   Payload user; `userId` is that user's Payload document id.
 * - `provider-only`: the operator has no linked Payload user (e.g. a
 *   provider-side admin who has never signed in through Payload).
 *   Fail-closed by design: the session still verifies and the actor
 *   is still audit-logged and still restricted by impersonation
 *   access policy, but the actor stays in explicit provider-id form
 *   instead of being dropped or dressed up as a Payload user id.
 *   The lookup re-runs on every verification, so the actor resolves
 *   as soon as the operator links a Payload user.
 */
export type ResolvedSessionActor =
  | {
      readonly kind: 'payload-user'
      readonly providerUserId: string
      readonly userId: UserId
    }
  | {
      readonly kind: 'provider-only'
      readonly providerUserId: string
    }

/**
 * How the credential was presented (CAP-13).
 *
 * There is deliberately no `'one-time'` channel: one-time tokens
 * (CAP-13b transports such as magic-link/OTP exchange codes) present
 * as `bearer` once redeemed into a session, so channel policies see
 * one honest value for every token-in-hand presentation.
 */
/**
 * Every {@link SessionChannel} value, for boundary validation. The
 * union derives from this tuple (single source, B16): a missing
 * member is now a compile error everywhere the union is consumed,
 * not a silently shorter validation list.
 */
export const sessionChannels = ['cookie', 'bearer', 'api-key', 'device'] as const

export type SessionChannel = (typeof sessionChannels)[number]

/**
 * An auth capability an adapter can declare on
 * {@link IdentityProviderPort.capabilities}. Declared, never
 * discovered: plugin options that need a capability fail at wiring
 * with `UnsupportedCapabilityError` when it is absent.
 */
export type Capability =
  | 'magic-link'
  | 'email-otp'
  | 'passkey'
  | 'oauth'
  | 'one-tap'
  | 'phone'
  | 'anonymous'
  | 'mfa'
  | 'impersonation'
  | 'revoke-user-sessions'
  | 'server-session-create'
  | 'server-session-list'
  | 'api-key-verify'

/** Result of a successful API-key verification (#54). */
export type ApiKeyVerification = {
  /** The provider user id the key belongs to. */
  readonly userId: string
  readonly name: string | null
  readonly start: string | null
  readonly prefix: string | null
  /** Opaque metadata exactly as stored; the app owns its shape. */
  readonly metadata: unknown
  readonly rateLimitEnabled: boolean | null
  readonly rateLimitRemaining: number | null
  readonly expiresAt: Date | null
  readonly permissions: string | null
}

/** Normalized profile returned by an identity provider. */
export type ProviderProfile = {
  readonly providerUserId: string
  /** The session's identity claims; the linking authority. */
  readonly identity: ProviderIdentityClaims
  /**
   * @deprecated Use `identity.email?.value`. Kept as an alias of the
   * email claim for one minor; `ensureLinkedUser` reads the claim.
   */
  readonly email: Email
  /**
   * @deprecated Use `identity.email?.verified`. Kept as an alias of
   * the email claim for one minor; `ensureLinkedUser` reads the claim.
   */
  readonly emailVerified: boolean
  readonly name: string | null
  readonly image: string | null
}

/** A live provider-side session. */
export type ProviderSession = {
  readonly sessionId: string
  readonly providerUserId: string
  /**
   * @deprecated Use `identity.email?.value`. Kept as an alias of the
   * email claim for one minor; new code reads the claim.
   */
  readonly email: Email
  /**
   * Whether the provider verified the email; gates JIT linking.
   *
   * @deprecated Use `identity.email?.verified`. Kept as an alias of
   * the email claim for one minor; new code reads the claim.
   */
  readonly emailVerified: boolean
  readonly expiresAt: Date
  /** The session's identity claims (PORT-1); gates JIT linking. */
  readonly identity: ProviderIdentityClaims
  /** How the session was proven; `unknown` when the provider can't tell. */
  readonly assurance: SessionAssurance
  /**
   * The operator acting as this user while impersonating (CAP-8):
   * `{ providerUserId }` for an impersonated session, `null` for a
   * plain one. Adapters that can tell must set it explicitly — a
   * malformed source value fails closed in the adapter, never `null`.
   */
  readonly actor: SessionActor | null
  /** Provider-native active tenant, if any (D1 decides its use). */
  readonly organizationId: string | null
  /** How the credential was presented (CAP-13). */
  readonly channel: SessionChannel
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/** Users via Payload Local API. Never raw database access. */
export interface UserRepository {
  findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError>
  findByEmail(email: Email): ResultAsync<UserRecord | null, RepositoryError>
  /**
   * Resolve an existing user by E.164 phone number (PORT-3). Optional:
   * only repositories whose users collection carries a phone field
   * implement it (the Payload phone field lands with CAP-9, Phase 6).
   * The verified-phone branch of a `LinkingPolicy` fails closed with
   * `UnverifiedIdentityError` when this is absent; it never falls back
   * to another identifier and never provisions.
   */
  readonly findByPhone?:
    ((phone: PhoneNumber) => ResultAsync<UserRecord | null, RepositoryError>) | undefined
  findByProviderIdentity(ref: ProviderIdentityRef): ResultAsync<UserRecord | null, RepositoryError>
  /**
   * Resolve the user document the PROVIDER itself owns by id (issue
   * #124): under an engine whose {@link IdentityProviderPort.providerUserIdsAreDocumentIds}
   * is true (adopt mode, `idStrategy: 'payload'`), the row the engine
   * created for a sign-up carries the provider user id AS the document
   * id, so a document found this way is the provider's own row — never
   * a third party's — and linking it needs no email proof.
   * Optional: repositories wired without such a provider omit it, and
   * the linking use case then never resolves by id.
   */
  readonly findByProviderOwnedId?:
    ((ref: ProviderIdentityRef) => ResultAsync<UserRecord | null, RepositoryError>) | undefined
  create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError>
  linkIdentity(userId: UserId, ref: ProviderIdentityRef): ResultAsync<UserRecord, RepositoryError>
  /**
   * Remove one linked identity row (CAP-14: provider unlink/delete).
   * Idempotent no-op when the identity is not linked. Never deletes
   * the user: Payload owns users (D9), so a provider-side deletion
   * unlinks and leaves the Payload document in place.
   */
  unlinkIdentity(userId: UserId, ref: ProviderIdentityRef): ResultAsync<UserRecord, RepositoryError>
  setRoles(userId: UserId, roles: readonly Role[]): ResultAsync<UserRecord, RepositoryError>
  /**
   * Sync the user's email to the provider's verified address. Idempotent
   * no-op when the address already matches. Fails with `UserExistsError`
   * when another user holds the address.
   */
  setEmail(userId: UserId, email: Email): ResultAsync<UserRecord, RepositoryError | UserExistsError>
  /**
   * Store a verified phone for the user (CAP-9). Optional like
   * `findByPhone`: only phone-capable repositories implement it.
   * Idempotent no-op when the number already matches; fails with
   * `RepositoryError` when another user holds the number, so a
   * verified claim can never silently steal an existing link target.
   */
  readonly setPhone?:
    ((userId: UserId, phone: PhoneNumber) => ResultAsync<UserRecord, RepositoryError>) | undefined
}

/**
 * An anonymous provider session recognized as a guest (CAP-10, D3):
 * a stable provider-side identity with NO Payload user, no roles,
 * and no Payload access. Applications may key anonymous state
 * (carts, drafts) on `id`; upgrading the provider account (BA
 * `onLinkAccount`) turns a later verified session into a normal
 * linked {@link Session} through the usual path.
 */
export type GuestPrincipal = {
  /** The provider-side anonymous user id (stable per guest). */
  readonly id: string
  readonly providerId: ProviderId
  readonly expiresAt: Date
}

/** Plugin-level sessions, resolved against users. */
export interface SessionPort {
  verify(
    headers: Headers
  ): ResultAsync<
    Session,
    | SessionInvalidError
    | SessionExpiredError
    | ChannelNotAdmittedError
    | UserSuspendedError
    | RepositoryError
  >
  revoke(session: Session): ResultAsync<void, UnknownProviderError | ProviderError>
  /**
   * Recognize an anonymous provider session as a {@link GuestPrincipal}
   * (CAP-10). Optional: session services without an anonymous-capable
   * provider omit it. Returns `null` when no live anonymous session
   * is presented; NEVER provisions or links a Payload user.
   */
  readonly guest?:
    ((headers: Headers) => ResultAsync<GuestPrincipal | null, RepositoryError>) | undefined
}

/**
 * One identity provider behind the port. Register via the registry.
 *
 * Providers own their OAuth dance (their SDK mounts its own routes and
 * persists via its database adapter); the plugin only needs to verify and
 * revoke provider sessions and bridge them to Payload users.
 */
export interface IdentityProviderPort {
  readonly id: ProviderId
  /**
   * Cookie names carrying this provider's session (e.g. Better Auth's
   * `better-auth.session_token`). Surfaces use them for middleware
   * fast-paths and for clearing stale provider cookies on logout — the
   * provider itself remains the only reader of their values.
   */
  readonly sessionCookieNames: readonly string[]
  /**
   * Clearing attributes for one session cookie on logout: `secure`
   * (required to overwrite `Secure` cookies, which prefix inference
   * misses when the name is customized), `domain`, `path`, `sameSite`.
   * Optional for backward compatibility — providers that omit it fall
   * back to prefix-derived attributes (see `expiringCookieOptions`).
   */
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
  /**
   * The coexistence window the provider's ENGINE was configured with
   * (issue #51/#72): legacy session cookie names honored read-only
   * until the ISO `until` date. The engine input is what acts; the
   * plugin's own `legacySessions` option exists only as a config-time
   * cross-check against this. Optional: providers whose engine has no
   * window (or predates the input) omit it.
   */
  readonly legacySessions?:
    | Readonly<{
        readonly until: string
        readonly cookieNames: readonly string[]
      }>
    | undefined
  /**
   * Extra provider cookies to expire on logout that do NOT themselves
   * indicate a live session, so they must stay out of
   * `sessionCookieNames` (middleware fast-paths read that list as
   * "signed in"). Example: Better Auth's `admin_session`, which holds
   * the impersonating operator's session token — leaving it behind on
   * logout would keep a resumable operator credential in the browser
   * after the user believes they signed out. Optional: providers
   * without such cookies omit it.
   */
  readonly logoutCookieNames?: readonly string[] | undefined
  /**
   * The capabilities this adapter honestly supports today (PORT-2).
   * Declared, never discovered: a plugin option or policy that needs
   * a capability absent here fails at wiring with
   * `UnsupportedCapabilityError` instead of silently degrading. An
   * adapter declares a capability only once it maps the provider's
   * native mechanism to the core claims/assurance vocabulary.
   */
  readonly capabilities: ReadonlySet<Capability>
  getSession(headers: Headers): ResultAsync<ProviderSession | null, ProviderError>
  revokeSession(sessionId: string): ResultAsync<void, ProviderError>
  /**
   * Revoke every live session of one provider user (CAP-7 suspend).
   * Optional: only adapters that declare `'revoke-user-sessions'` in
   * {@link IdentityProviderPort.capabilities} implement it; providers
   * on stateless JWT sessions honestly omit it (the Payload-side
   * suspended check still refuses at verify time).
   */
  readonly revokeUserSessions?:
    ((providerUserId: string) => ResultAsync<void, ProviderError>) | undefined
  /**
   * Mint a provider session for one provider user — the supported
   * server-side path behind `authLinkServer.createSessionFor` (issue
   * #54). Optional: only adapters that declare
   * `'server-session-create'` implement it; the server API refuses
   * session creation with a typed error when the configured provider
   * cannot (e.g. stateless Auth.js).
   */
  readonly createProviderSession?:
    | ((
        providerUserId: string,
        options: {
          readonly expiresAt: Date
          /**
           * A server-vouched step-up proof: set ONLY when the server
           * has itself verified a second factor for this mint (there
           * is no client input to trust here). Records the
           * authentication method on the session row; the default
           * (`false`) marks the session `mfa: false` on read-back —
           * a mint ran no 2FA challenge.
           */
          readonly mfaProof?: boolean | undefined
        }
      ) => ResultAsync<
        {
          readonly sessionId: string
          readonly token: string
          /** The expiry STORED on the session row, when the row reports it. */
          readonly storedExpiresAt: Date | null
        },
        ProviderError
      >)
    | undefined
  /**
   * Enumerate one provider user's live sessions — the read side of
   * `authLinkServer.listSessions`. Optional: only adapters declaring
   * `'server-session-list'` implement it.
   */
  readonly listProviderSessions?:
    | ((providerUserId: string) => ResultAsync<
        readonly {
          readonly sessionId: string
          readonly expiresAt: Date | null
        }[],
        ProviderError
      >)
    | undefined
  /**
   * Verify an API key and resolve its owner + metadata —
   * `authLinkServer.verifyApiKey`. Optional: only adapters declaring
   * `'api-key-verify'` implement it.
   */
  readonly verifyApiKey?:
    ((key: string) => ResultAsync<ApiKeyVerification | null, ProviderError>) | undefined
  /**
   * The provider's correctly signed session cookie VALUE for one
   * session token, `token.<signature>` — `authLinkServer.sessionCookie`.
   * Inject it into a request's `Cookie` header; the provider accepts
   * only the signed form. Signing is async (the provider resolves its
   * engine's secret on first use). For the full `Set-Cookie` line to
   * set on a response, use {@link IdentityProviderPort.sessionCookieLine}
   * or `authLinkServer.createSessionFor(...).setCookie`. Optional:
   * providers whose session transport is not a cookie (stateless
   * Auth.js) omit it.
   */
  readonly sessionCookie?: ((token: string) => Promise<string>) | undefined
  /**
   * The full `Set-Cookie` line for one session token — cookie name,
   * signed value, and the provider's write attributes (Path, HttpOnly,
   * SameSite, Secure, Domain, Max-Age). This is what
   * `authLinkServer.createSessionFor(...)` returns as `setCookie`.
   * Optional: providers without `sessionCookie` omit it too.
   */
  readonly sessionCookieLine?: ((token: string) => Promise<string>) | undefined
  /**
   * The provider's user ids ARE the document ids of the mapped users
   * collection (issue #124): adopt mode with `idStrategy: 'payload'`,
   * where the engine creates user rows in the host Payload collection
   * using its own user id as the document id. A document resolved by
   * that id is the provider's own row — the JIT link may attach to it
   * without an email-ownership proof, because nobody but the engine
   * can mint a document with that id (Payload ids are server-generated;
   * client-supplied ids are refused). Optional: engines that mint
   * their own row ids (the default `idStrategy: 'ba'`) omit it, and
   * id-based linking never runs for them.
   */
  readonly providerUserIdsAreDocumentIds?: boolean | undefined
  /**
   * Enumerate every session id presented by this request beyond the
   * active session (CAP-13b multi-session logout): the ids are
   * provider-verified handles suitable for {@link revokeSession},
   * never parsed out of cookie names. Optional: only multi-session
   * capable adapters implement it; logout revokes each returned id
   * and expires every presented multi-session cookie.
   */
  readonly listPresentedSessionIds?:
    ((headers: Headers) => ResultAsync<readonly string[], ProviderError>) | undefined
  /**
   * Names of presented cookies that must be expired on logout in
   * addition to `sessionCookieNames`/`logoutCookieNames`, computed
   * from the actual request (CAP-13b: multi-session cookie names are
   * per-token dynamic, so no static list can contain them). Optional.
   */
  readonly presentedLogoutCookieNames?: ((headers: Headers) => readonly string[]) | undefined
  /**
   * Subscribe to this provider's identity lifecycle events (CAP-14),
   * translated from its native hooks. Returns an unsubscribe
   * function. Optional: adapters whose provider exposes no usable
   * hooks omit it and rely on read-time sync. The plugin subscribes
   * at `onInit` (the composition root) and applies events through
   * `UserRepository`; builders never wire this by hand.
   */
  readonly onIdentityEvent?: ((handler: IdentityEventHandler) => () => void) | undefined
}

/**
 * Assert a provider declares every required capability (PORT-2
 * enforcement). Throws {@link UnsupportedCapabilityError} naming the
 * first missing capability — wiring-time fail-fast, so an option or
 * policy that needs a capability the adapter does not honestly
 * support never silently degrades at request time. Composition
 * roots call this for each capability-gated option they accept.
 */
export function assertCapabilities(
  provider: Pick<IdentityProviderPort, 'id' | 'capabilities'>,
  required: readonly Capability[]
): void {
  for (const capability of required) {
    if (!provider.capabilities.has(capability)) {
      throw new UnsupportedCapabilityError(provider.id, capability)
    }
  }
}

/**
 * Run one provider operation behind the port: invoke `call`, validate the
 * unknown result with `narrow`, and map every failure to `ProviderError`.
 * The single place where unexpected provider throws (SDK faults, malformed
 * payloads rejected by `narrow`) become typed port errors with their cause
 * — port implementations use this instead of hand-rolled `try` blocks.
 */
export function runProviderOperation<T>(
  providerId: ProviderId,
  operation: string,
  call: () => Promise<unknown>,
  narrow: (value: unknown) => T
): ResultAsync<T, ProviderError> {
  return ResultAsync.fromPromise(
    call(),
    (cause) => new ProviderError(providerId, operation, { cause })
  ).andThen((result) => {
    try {
      return ok(narrow(result))
    } catch (error) {
      return err(
        error instanceof ProviderError
          ? error
          : new ProviderError(providerId, operation, { cause: error })
      )
    }
  })
}

/** Cookie `SameSite` attribute values. */
export type SameSite = 'lax' | 'strict' | 'none'

/** Framework-free cookie attributes for {@link CookiePort}. */
export type CookieOptions = {
  readonly path?: string | undefined
  readonly maxAge?: number | undefined
  readonly httpOnly?: boolean | undefined
  readonly secure?: boolean | undefined
  readonly sameSite?: SameSite | undefined
  readonly domain?: string | undefined
  readonly partitioned?: boolean | undefined
}

/** Cookie transport over Web-standard `Headers`. Implemented per framework. */
export interface CookiePort {
  read(headers: Headers, name: string): string | undefined
  write(headers: Headers, name: string, value: string, options?: CookieOptions): void
  clear(headers: Headers, name: string, options?: CookieOptions): void
}

/** Storage transactions. Adapters implement real transactions — no no-ops. */
export interface TransactionPort {
  run<T, E>(fn: () => ResultAsync<T, E>): ResultAsync<T, E>
}

/** Structured log fields; values must be JSON-safe, never credentials. */
export type LogFields = { readonly [key: string]: unknown }

/** Structured logging. Adapters forward to pino; never `console.*`. */
export interface LoggerPort {
  debug(message: string, fields?: LogFields): void
  info(message: string, fields?: LogFields): void
  warn(message: string, fields?: LogFields): void
  error(message: string, fields?: LogFields): void
  child(bindings: LogFields): LoggerPort
}

/** Distributed tracing. Adapters implement with OpenTelemetry spans. */
export interface TracerPort {
  withSpan<T>(name: string, attributes: LogFields, fn: () => Promise<T>): Promise<T>
}

/** Time. Injected so domain logic stays deterministic in tests. */
export interface ClockPort {
  now(): Date
}

/** Id generation. Injected so domain logic stays deterministic in tests. */
export interface IdPort {
  newId(): string
}
