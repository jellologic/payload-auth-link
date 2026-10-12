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
