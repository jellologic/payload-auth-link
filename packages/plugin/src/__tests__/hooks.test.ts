import type { CollectionMap } from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import { normalizeUserEmailHook } from '../hooks.js'

const map: CollectionMap = {
  usersCollection: 'users',
  emailField: 'email',
  rolesField: 'roles',
  identitiesField: 'identities',
}

type HookArgs = Parameters<ReturnType<typeof normalizeUserEmailHook>>[0]

function run(data: Record<string, unknown> | undefined): unknown {
  return normalizeUserEmailHook(map)({ data } as unknown as HookArgs)
}

describe('normalizeUserEmailHook', () => {
  it('lowercases a mixed-case email in place', () => {
    const data = { email: 'Mixed@Example.COM' }
    expect(run(data)).toEqual({ email: 'mixed@example.com' })
  })

  it('leaves an already-canonical email untouched', () => {
    const data = { email: 'plain@example.com' }
    expect(run(data)).toBe(data)
    expect(data.email).toBe('plain@example.com')
  })

  it('passes through data without a string email', () => {
    expect(run({ email: 42 })).toEqual({ email: 42 })
    expect(run({ name: 'no email' })).toEqual({ name: 'no email' })
  })

  it('passes through a missing data object', () => {
    expect(run(undefined)).toBeUndefined()
  })
})
