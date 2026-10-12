import { AuthLinkError } from '@payload-auth-link/core'

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
