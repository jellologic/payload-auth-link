import { AuthLinkError } from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import {
  AdapterOperationError,
  UnknownModelError,
  UnsupportedOperatorError,
  UnsupportedSchemaError,
} from '../errors.js'

describe('provider error taxonomy', () => {
  it('extends AuthLinkError with stable codes', () => {
    const cases: Array<[AuthLinkError, string]> = [
      [new AdapterOperationError('find'), 'ADAPTER_OPERATION_FAILED'],
      [new UnknownModelError('member'), 'UNKNOWN_MODEL'],
      [new UnsupportedOperatorError('contains'), 'UNSUPPORTED_OPERATOR'],
      [new UnsupportedSchemaError('x'), 'UNSUPPORTED_SCHEMA'],
    ]
    for (const [error, code] of cases) {
      expect(error).toBeInstanceOf(AuthLinkError)
      expect(error).toBeInstanceOf(Error)
      expect(error.code).toBe(code)
      expect(error.name).toBe(error.constructor.name)
    }
  })

  it('preserves the operation and cause on operation errors', () => {
    const cause = new Error('payload down')
    const error = new AdapterOperationError('find', { cause })
    expect(error.operation).toBe('find')
    expect(error.cause).toBe(cause)
    expect(error.message).toContain('find')
  })
})
