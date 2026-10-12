import { err, ok, ResultAsync } from 'neverthrow'
import { z } from 'zod'
import type { Email } from './email.js'
import {
  InvalidProviderIdError,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnknownProviderError,
  UserExistsError,
} from './errors.js'
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
}

/** Registration input: every provisioned user starts with roles. */
export type NewUser = {
  readonly email: Email
  readonly roles: readonly Role[]
  readonly identity?: ProviderIdentityRef | undefined
}

/** A verified plugin-level session: provider-agnostic, role-free. */
export type Session = {
  readonly id: SessionId
  readonly userId: UserId
  readonly providerId: ProviderId
  readonly expiresAt: Date
}

/** Normalized profile returned by an identity provider. */
export type ProviderProfile = {
  readonly providerUserId: string
  readonly email: Email
  readonly emailVerified: boolean
  readonly name: string | null
  readonly image: string | null
}

/** A live provider-side session. */
export type ProviderSession = {
  readonly sessionId: string
  readonly providerUserId: string
  readonly email: Email
  /** Whether the provider verified the email; gates JIT linking. */
  readonly emailVerified: boolean
  readonly expiresAt: Date
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/** Users via Payload Local API. Never raw database access. */
export interface UserRepository {
  findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError>
  findByEmail(email: Email): ResultAsync<UserRecord | null, RepositoryError>
  findByProviderIdentity(ref: ProviderIdentityRef): ResultAsync<UserRecord | null, RepositoryError>
  create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError>
  linkIdentity(userId: UserId, ref: ProviderIdentityRef): ResultAsync<UserRecord, RepositoryError>
  setRoles(userId: UserId, roles: readonly Role[]): ResultAsync<UserRecord, RepositoryError>
  /**
   * Sync the user's email to the provider's verified address. Idempotent
   * no-op when the address already matches. Fails with `UserExistsError`
   * when another user holds the address.
   */
  setEmail(userId: UserId, email: Email): ResultAsync<UserRecord, RepositoryError | UserExistsError>
}

/** Plugin-level sessions, resolved against users. */
export interface SessionPort {
  verify(
    headers: Headers
  ): ResultAsync<Session, SessionInvalidError | SessionExpiredError | RepositoryError>
  revoke(session: Session): ResultAsync<void, UnknownProviderError | ProviderError>
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
  getSession(headers: Headers): ResultAsync<ProviderSession | null, ProviderError>
  revokeSession(sessionId: string): ResultAsync<void, ProviderError>
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
