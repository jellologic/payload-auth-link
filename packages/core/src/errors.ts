/**
 * Typed error taxonomy. Expected failures travel as `Result<T, E>` values;
 * only programmer errors and truly unexpected faults are thrown.
 *
 * Domain errors (invalid input at a boundary) stay distinct from application
 * errors (a valid operation that failed). Web adapters map them to status
 * codes; core never touches HTTP.
 */
/**
 * Base error: machine-readable `code`, human `message`, optional
 * `cause`. Leaf classes fix their code; adapters map codes to HTTP.
 */
export class AuthLinkError extends Error {
  readonly code: string

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = new.target.name
    this.code = code
  }
}

// ---------------------------------------------------------------------------
// Domain errors: the input itself is invalid.
// ---------------------------------------------------------------------------

/** `INVALID_EMAIL`: raw input failed {@link parseEmail}. */
export class InvalidEmailError extends AuthLinkError {
  constructor(detail: string) {
    super('INVALID_EMAIL', `Invalid email: ${detail}`)
  }
}

/** `INVALID_PHONE_NUMBER`: raw input failed {@link parsePhoneNumber}. */
export class InvalidPhoneNumberError extends AuthLinkError {
  constructor(detail: string) {
    super('INVALID_PHONE_NUMBER', `Invalid phone number: ${detail}`)
  }
}

/** `INVALID_ROLE`: unknown role string at a boundary. */
export class InvalidRoleError extends AuthLinkError {
  constructor(detail: string) {
    super('INVALID_ROLE', `Invalid role: ${detail}`)
  }
}

/** `INVALID_PROVIDER_ID`: malformed provider registry id. */
export class InvalidProviderIdError extends AuthLinkError {
  constructor(detail: string) {
    super('INVALID_PROVIDER_ID', `Invalid provider id: ${detail}`)
  }
}

/** `INVALID_COLLECTION_MAP`: bad slug/field map in plugin options. */
export class InvalidCollectionMapError extends AuthLinkError {
  constructor(detail: string) {
    super('INVALID_COLLECTION_MAP', `Invalid collection map: ${detail}`)
  }
}

/** `INVALID_CONFIG`: startup validation rejected the config. Thrown, never returned. */
export class InvalidConfigError extends AuthLinkError {
  constructor(detail: string) {
    super('INVALID_CONFIG', `Invalid config: ${detail}`)
  }
}

/** `DUPLICATE_PROVIDER`: two providers registered under one id. */
export class DuplicateProviderError extends AuthLinkError {
  constructor(providerId: string) {
    super('DUPLICATE_PROVIDER', `Provider already registered: ${providerId}`)
  }
}

/** `UNKNOWN_PROVIDER`: registry lookup for an unregistered id. */
export class UnknownProviderError extends AuthLinkError {
  constructor(providerId: string) {
    super('UNKNOWN_PROVIDER', `Unknown provider: ${providerId}`)
  }
}

// ---------------------------------------------------------------------------
// Application errors: valid operations that failed.
// ---------------------------------------------------------------------------

/** `USER_EXISTS`: registration raced or replayed an existing email. */
export class UserExistsError extends AuthLinkError {
  constructor(email: string) {
    super('USER_EXISTS', `User already exists: ${email}`)
  }
}

/** `REPOSITORY_ERROR`: user storage failed; see `cause`. */
export class RepositoryError extends AuthLinkError {
  constructor(operation: string, options?: { cause?: unknown }) {
    super('REPOSITORY_ERROR', `Repository operation failed: ${operation}`, options)
  }
}

/** `SESSION_EXPIRED`: a structurally valid session passed its expiry. */
export class SessionExpiredError extends AuthLinkError {
  constructor() {
    super('SESSION_EXPIRED', 'Session has expired')
  }
}

/** `SESSION_INVALID`: no session, malformed session, or link failure. Maps to 401. */
export class SessionInvalidError extends AuthLinkError {
  constructor(detail: string) {
    super('SESSION_INVALID', `Session is invalid: ${detail}`)
  }
}

/**
 * `CHANNEL_NOT_ADMITTED`: a live provider session was presented on a
 * channel the plugin does not admit (CAP-13a `admitChannels`, default
 * `['cookie']`). A valid credential on an unadmitted channel is still
 * refused — maps to 401, and verification stops at the presenting
 * provider instead of trying later ones. Distinct from
 * {@link SessionInvalidError} so operators can tell "bad credential"
 * from "good credential, wrong presentation" in logs.
 */
export class ChannelNotAdmittedError extends AuthLinkError {
  readonly channel: string
  readonly admittedChannels: readonly string[]

  constructor(channel: string, admittedChannels: readonly string[]) {
    super(
      'CHANNEL_NOT_ADMITTED',
      `Session channel not admitted: ${channel} (admitted: ${admittedChannels.join(', ') || 'none'})`
    )
    this.channel = channel
    this.admittedChannels = [...admittedChannels]
  }
}

/**
 * `USER_SUSPENDED`: the Payload user behind an otherwise valid
 * provider session is suspended (CAP-7). Payload owns the suspension,
 * so this refuses every provider and every session strategy —
 * including stateless JWTs no provider can revoke. Maps to 401 at
 * session endpoints (the session is not usable), with the suspension
 * expiry carried for logs/UI copy. Never leak `reason` to clients by
 * default; it is operator-facing.
 */
export class UserSuspendedError extends AuthLinkError {
  readonly suspendedUntil: Date

  constructor(suspendedUntil: Date) {
    super('USER_SUSPENDED', `User is suspended until ${suspendedUntil.toISOString()}`)
    this.suspendedUntil = suspendedUntil
  }
}

/** `FORBIDDEN`: authenticated but missing required roles. Maps to 403. */
export class ForbiddenError extends AuthLinkError {
  constructor(detail: string) {
    super('FORBIDDEN', `Forbidden: ${detail}`)
  }
}

/** `UNVERIFIED_EMAIL`: refused to link an unverified provider email. */
export class UnverifiedEmailError extends AuthLinkError {
  constructor(email: string) {
    super(
      'UNVERIFIED_EMAIL',
      `Refusing to link unverified provider email to an existing user: ${email}`
    )
  }
}

/**
 * `UNVERIFIED_IDENTITY`: refused to link because the session carries no
 * verified identity claim the active policy can link on (no email claim,
 * no verified phone where phone-linking is enabled, an anonymous
 * identity, …). Sibling of {@link UnverifiedEmailError} for the
 * claim-based policies (PORT-3/CAP-9); declared now with PORT-1 so both
 * adapters and policies share one taxonomy.
 */
export class UnverifiedIdentityError extends AuthLinkError {
  constructor(detail: string) {
    super('UNVERIFIED_IDENTITY', `Refusing to link unverified identity: ${detail}`)
  }
}

/**
 * `MFA_REQUIRED`: the session is authenticated but a policy
 * (`requireMfaForRoles`, CAP-6) demands multi-factor assurance this
 * session does not carry. Enforced by the plugin's role projection
 * (CAP-6) and the web `requireRoles({ requireMfa: true })` helper.
 */
export class MfaRequiredError extends AuthLinkError {
  constructor(detail: string) {
    super('MFA_REQUIRED', `Multi-factor authentication required: ${detail}`)
  }
}

/**
 * `UNSUPPORTED_CAPABILITY`: a plugin option or policy needs a
 * `Capability` the registered provider does not declare. Thrown at
 * wiring time (fail fast) — behavior never silently degrades.
 */
export class UnsupportedCapabilityError extends AuthLinkError {
  readonly providerId: string
  readonly capability: string

  constructor(providerId: string, capability: string) {
    super(
      'UNSUPPORTED_CAPABILITY',
      `Provider ${providerId} does not support required capability: ${capability}`
    )
    this.providerId = providerId
    this.capability = capability
  }
}

/**
 * `PROVIDER_ERROR`: an identity provider failed; `providerId` says
 * which. Session reads treat this as anonymous (fail closed).
 */
export class ProviderError extends AuthLinkError {
  readonly providerId: string

  constructor(providerId: string, operation: string, options?: { cause?: unknown }) {
    super('PROVIDER_ERROR', `Provider ${providerId} failed during ${operation}`, options)
    this.providerId = providerId
  }
}
