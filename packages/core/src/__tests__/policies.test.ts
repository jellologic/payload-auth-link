import { describe, expect, it } from 'vitest'
import {
  effectiveRoles,
  emailDomainAllowed,
  emailDomainOf,
  isSuspendedAt,
  mfaSatisfied,
  withheldRoles,
} from '../policies.js'
import { parseRole, type Role } from '../roles.js'

function role(value: string): Role {
  const parsed = parseRole(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

const admin = role('admin')
const user = role('user')
const roles = [admin, user]

describe('mfaSatisfied (CAP-6)', () => {
  it('only the literal true satisfies; unknown and absent fail closed', () => {
    expect(mfaSatisfied({ methods: 'unknown', mfa: true })).toBe(true)
    expect(mfaSatisfied({ methods: 'unknown', mfa: false })).toBe(false)
    expect(mfaSatisfied({ methods: 'unknown', mfa: 'unknown' })).toBe(false)
    expect(mfaSatisfied(undefined)).toBe(false)
  })
})

describe('effectiveRoles / withheldRoles (CAP-6)', () => {
  it('withholds gated roles without MFA proof, keeps the rest', () => {
    expect(effectiveRoles(roles, { methods: 'unknown', mfa: 'unknown' }, [admin])).toEqual([user])
    expect(withheldRoles(roles, { methods: 'unknown', mfa: false }, [admin])).toEqual([admin])
    expect(effectiveRoles(roles, undefined, [admin])).toEqual([user])
  })

  it('restores gated roles when MFA is proven', () => {
    expect(effectiveRoles(roles, { methods: ['password'], mfa: true }, [admin])).toEqual(roles)
    expect(withheldRoles(roles, { methods: ['password'], mfa: true }, [admin])).toEqual([])
  })

  it('is a no-op when no policy is configured', () => {
    expect(effectiveRoles(roles, undefined, [])).toBe(roles)
    expect(withheldRoles(roles, undefined, [])).toEqual([])
  })
})

describe('SSO domain guard (CAP-15)', () => {
  it('requires an exact verified-domain match, case-insensitively', () => {
    expect(emailDomainOf('User@Example.COM')).toBe('example.com')
    expect(emailDomainAllowed('a@example.com', ['example.com'])).toBe(true)
    expect(emailDomainAllowed('a@EXAMPLE.com', ['Example.Com'])).toBe(true)
    expect(emailDomainAllowed('a@mail.example.com', ['example.com'])).toBe(false)
    expect(emailDomainAllowed('a@example.com.evil.test', ['example.com'])).toBe(false)
    expect(emailDomainAllowed('a@example.com', [])).toBe(false)
  })
})

describe('isSuspendedAt (CAP-7)', () => {
  const now = new Date('2026-10-12T00:00:00.000Z')

  it('is in force only while the expiry is in the future', () => {
    expect(isSuspendedAt(new Date(now.getTime() + 1), now)).toBe(true)
    expect(isSuspendedAt(now, now)).toBe(false)
    expect(isSuspendedAt(new Date(now.getTime() - 1), now)).toBe(false)
    expect(isSuspendedAt(null, now)).toBe(false)
    expect(isSuspendedAt(undefined, now)).toBe(false)
  })
})
