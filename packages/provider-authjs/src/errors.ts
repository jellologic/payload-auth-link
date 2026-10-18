import { AuthLinkError } from '@payload-auth-link/core'

/** An Auth.js adapter operation against Payload failed. Wraps the cause. */
export class AdapterOperationError extends AuthLinkError {
  constructor(operation: string, options?: { cause?: unknown }) {
    super('ADAPTER_OPERATION_FAILED', `Auth.js adapter ${operation} failed`, options)
  }
}

/** The adapter read a Payload document it cannot honestly map. Loud, not null. */
export class AdapterMappingError extends AuthLinkError {
  constructor(detail: string) {
    super('ADAPTER_MAPPING_FAILED', `Auth.js adapter cannot map document: ${detail}`)
  }
}

/** A credentials password violates the minimum length policy. */
export class WeakPasswordError extends AuthLinkError {
  constructor(minLength: number) {
    super('WEAK_PASSWORD', `Auth.js credentials password must be at least ${minLength} characters`)
  }
}

/**
 * A builder `session` callback returned a value that cannot be the
 * session JSON (a cycle, or not an object). Auth.js could not
 * serialize it either; failing here means the credential scrub is
 * never skipped.
 */
export class SessionShapeError extends AuthLinkError {
  constructor(detail: string) {
    super('SESSION_SHAPE_INVALID', `Auth.js builder session callback: ${detail}`)
  }
}
