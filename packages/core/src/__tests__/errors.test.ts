import { describe, expect, it } from 'vitest'
import {
  AuthLinkError,
  ForbiddenError,
  InvalidConfigError,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UserExistsError,
} from '../errors.js'

describe('error taxonomy', () => {
  it('carries stable codes and names', () => {
    const cases: Array<[AuthLinkError, string]> = [
      [new InvalidConfigError('x'), 'INVALID_CONFIG'],
      [new UserExistsError('a@b.c'), 'USER_EXISTS'],
      [new RepositoryError('find'), 'REPOSITORY_ERROR'],
      [new SessionExpiredError(), 'SESSION_EXPIRED'],
      [new SessionInvalidError('x'), 'SESSION_INVALID'],
      [new ForbiddenError('x'), 'FORBIDDEN'],
      [new ProviderError('better-auth', 'x'), 'PROVIDER_ERROR'],
    ]
    for (const [error, code] of cases) {
      expect(error).toBeInstanceOf(AuthLinkError)
      expect(error).toBeInstanceOf(Error)
      expect(error.code).toBe(code)
      expect(error.name).toBe(error.constructor.name)
    }
  })

  it('preserves causes', () => {
    const cause = new Error('db down')
    const error = new RepositoryError('create', { cause })
    expect(error.cause).toBe(cause)
  })

  it('keeps the provider id on provider errors', () => {
    expect(new ProviderError('authjs', 'x').providerId).toBe('authjs')
  })
})
