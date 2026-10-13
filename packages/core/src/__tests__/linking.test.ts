import { describe, expect, it } from 'vitest'
import { InvalidConfigError } from '../errors.js'
import { defaultLinkingPolicy, parseLinkingPolicy } from '../linking.js'

describe('linking policy (PORT-3)', () => {
  it('defaults to verified-email', () => {
    expect(defaultLinkingPolicy).toEqual({ kind: 'verified-email' })
  })

  it('parses both declared policies', () => {
    const emailOnly = parseLinkingPolicy({ kind: 'verified-email' })
    expect(emailOnly.isOk() && emailOnly.value).toEqual({ kind: 'verified-email' })
    const withPhone = parseLinkingPolicy({ kind: 'verified-email-or-phone' })
    expect(withPhone.isOk() && withPhone.value).toEqual({ kind: 'verified-email-or-phone' })
  })

  it('rejects unknown kinds and unknown keys instead of falling back to the default', () => {
    for (const value of [
      { kind: 'verified-phone' },
      { kind: 'verified-email', allowPhone: true },
      {},
      null,
      'verified-email',
    ]) {
      const result = parseLinkingPolicy(value)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(InvalidConfigError)
      }
    }
  })
})
