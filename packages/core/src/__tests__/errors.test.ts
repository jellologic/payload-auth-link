import { describe, expect, it } from 'vitest'
import {
  AuthLinkError,
  ForbiddenError,
  InvalidConfigError,
  InvalidPhoneNumberError,
  ChannelNotAdmittedError,
  MfaRequiredError,
  ProviderError,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnsupportedCapabilityError,
  UnverifiedIdentityError,
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
      [new ChannelNotAdmittedError('bearer', ['cookie']), 'CHANNEL_NOT_ADMITTED'],
      [new ForbiddenError('x'), 'FORBIDDEN'],
      [new ProviderError('better-auth', 'x'), 'PROVIDER_ERROR'],
      [new InvalidPhoneNumberError('x'), 'INVALID_PHONE_NUMBER'],
      [new UnverifiedIdentityError('x'), 'UNVERIFIED_IDENTITY'],
      [new MfaRequiredError('x'), 'MFA_REQUIRED'],
      [new UnsupportedCapabilityError('authjs', 'mfa'), 'UNSUPPORTED_CAPABILITY'],
    ]
    for (const [error, code] of cases) {
      expect(error).toBeInstanceOf(AuthLinkError)
      expect(error).toBeInstanceOf(Error)
      expect(error.code).toBe(code)
      expect(error.name).toBe(error.constructor.name)
    }
  })

  it('names the refused and admitted channels (CAP-13a)', () => {
    const error = new ChannelNotAdmittedError('bearer', ['cookie'])
    expect(error.channel).toBe('bearer')
    expect(error.admittedChannels).toEqual(['cookie'])
    expect(error.message).toContain('bearer')
  })

  it('preserves causes', () => {
    const cause = new Error('db down')
    const error = new RepositoryError('create', { cause })
    expect(error.cause).toBe(cause)
  })

  it('keeps the provider id on provider errors', () => {
    expect(new ProviderError('authjs', 'x').providerId).toBe('authjs')
  })

  it('keeps provider id and capability on unsupported-capability errors (PORT-2)', () => {
    const error = new UnsupportedCapabilityError('authjs', 'mfa')
    expect(error.providerId).toBe('authjs')
    expect(error.capability).toBe('mfa')
    expect(error.message).toContain('mfa')
  })
})
