import { AuthLinkError, ProviderError, wellKnownProviderIds } from '@payload-auth-link/core'

/** A Better Auth adapter operation against Payload failed. Wraps the cause. */
export class AdapterOperationError extends AuthLinkError {
  readonly operation: string

  constructor(operation: string, options?: { cause?: unknown }) {
    super(
      'ADAPTER_OPERATION_FAILED',
      `Better Auth Payload adapter failed during ${operation}`,
      options
    )
    this.operation = operation
  }
}

/** A Better Auth model with no mapped Payload collection. */
export class UnknownModelError extends AuthLinkError {
  constructor(model: string) {
    super('UNKNOWN_MODEL', `No Payload collection mapped for Better Auth model: ${model}`)
  }
}

/** A `Where` operator with no faithful Payload translation. */
export class UnsupportedOperatorError extends AuthLinkError {
  constructor(operator: string) {
    super('UNSUPPORTED_OPERATOR', `Better Auth operator has no Payload translation: ${operator}`)
  }
}

/** A Better Auth schema customization the Payload mapping cannot honor. */
export class UnsupportedSchemaError extends AuthLinkError {
  constructor(detail: string) {
    super('UNSUPPORTED_SCHEMA', `Better Auth schema is not mappable to Payload: ${detail}`)
  }
}

/**
 * A valid API key whose owner (`referenceId`) is not a Better Auth
 * user — in practice an organization-owned key
 * (`apiKey({ references: 'organization' })`), whose `referenceId` is an
 * organization id. `verifyApiKey` resolves a USER; returning an
 * organization id as `userId` would confuse principals, so such keys
 * are refused (fail closed) until organization-owned keys are
 * supported. A `ProviderError`, so every existing failure path treats
 * it as a refusal.
 */
export class UnsupportedApiKeyOwnerError extends ProviderError {
  /** The key's owner reference (an organization id, or a deleted user's id). */
  readonly referenceId: string

  constructor(referenceId: string) {
    super(
      wellKnownProviderIds.betterAuth,
      "verifyApiKey: the key's owner is not a user; organization-owned API keys (references: 'organization') are not supported"
    )
    this.referenceId = referenceId
  }
}
