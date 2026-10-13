import { InvalidConfigError } from '@payload-auth-link/core'
import type { CollectionConfig } from 'payload'
import { describe, expect, it } from 'vitest'
import { applyUsersCollection, fieldName } from '../collections.js'
import { wireOptions } from '../options.js'
import { createAuthLinkStrategy, strategyName } from '../strategy.js'
import { createStubProvider } from './stub-provider.js'

function wired() {
  const { provider } = createStubProvider()
  const options = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [provider],
  })
  return { options, strategy: createAuthLinkStrategy(options) }
}

describe('applyUsersCollection', () => {
  it('creates the users collection when missing', () => {
    const { options, strategy } = wired()
    const result = applyUsersCollection([], options, strategy)
    expect(result).toHaveLength(1)
    const users = result[0]
    expect(users?.slug).toBe('users')
    expect(users?.fields.map((field) => fieldName(field))).toEqual([
      'roles',
      'identities',
      'phone',
      'suspendedUntil',
      'suspendReason',
    ])
    expect(users?.auth).toMatchObject({ strategies: [{ name: strategyName }] })
    expect(users?.hooks?.beforeValidate).toHaveLength(1)
  })

  it('extends an existing collection without overwriting', () => {
    const { options, strategy } = wired()
    const hook = () => undefined
    const existing: CollectionConfig = {
      slug: 'users',
      auth: true,
      fields: [{ name: 'nickname', type: 'text' }],
      hooks: { beforeValidate: [hook] },
    }
    const result = applyUsersCollection([existing], options, strategy)
    const users = result[0]
    expect(users?.fields.map((field) => fieldName(field))).toEqual([
      'nickname',
      'roles',
      'identities',
      'phone',
      'suspendedUntil',
      'suspendReason',
    ])
    expect(users?.hooks?.beforeValidate).toHaveLength(2)
    expect(users?.hooks?.beforeValidate?.[0]).toBe(hook)
    const auth = users?.auth
    expect(typeof auth === 'object' && auth !== null && 'strategies' in auth).toBe(true)
  })

  it('appends to existing strategies without duplicating', () => {
    const { options, strategy } = wired()
    const other = { name: 'other', authenticate: () => Promise.resolve({ user: null }) }
    const existing: CollectionConfig = {
      slug: 'users',
      auth: { strategies: [other, strategy] },
      fields: [],
    }
    const result = applyUsersCollection([existing], options, strategy)
    const auth = result[0]?.auth
    if (typeof auth !== 'object' || auth === null || !('strategies' in auth)) {
      throw new Error('expected strategies array')
    }
    expect(auth.strategies?.map((candidate) => candidate.name)).toEqual(['other', strategyName])
  })

  it('throws on field-name collisions', () => {
    const { options, strategy } = wired()
    const existing: CollectionConfig = {
      slug: 'users',
      fields: [{ name: 'roles', type: 'text' }],
    }
    expect(() => applyUsersCollection([existing], options, strategy)).toThrow(InvalidConfigError)
  })

  describe('adopting an existing roles field (migration from payload-auth-style schemas)', () => {
    const compatible: CollectionConfig = {
      slug: 'users',
      fields: [
        {
          name: 'roles',
          type: 'select',
          hasMany: true,
          options: [
            { label: 'admin', value: 'admin' },
            { label: 'user', value: 'user' },
            { label: 'staff', value: 'staff' },
          ],
        },
      ],
    }

    it('adopts a compatible multi-select covering every configured role', () => {
      const { options, strategy } = wired()
      const result = applyUsersCollection([compatible], options, strategy)
      const users = result[0] as CollectionConfig
      const roles = users.fields.find((field) => fieldName(field) === 'roles') as Record<
        string,
        unknown
      >
      // Governance imposed; host options preserved.
      expect(roles.required).toBe(true)
      expect(roles.defaultValue).toEqual(['user'])
      const access = roles.access as { create?: unknown; update?: unknown; read?: unknown }
      expect(typeof access.create).toBe('function')
      expect(typeof access.update).toBe('function')
      expect(typeof access.read).toBe('function')
      expect(roles.options).toEqual(
        compatible.fields[0] && (compatible.fields[0] as Record<string, unknown>).options
      )
      // The identity rows and governance fields are still injected.
      expect(users.fields.some((field) => fieldName(field) === 'identities')).toBe(true)
    })

    it('rejects single-select and missing-role shapes with remediation', () => {
      const { options, strategy } = wired()
      const single: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'roles', type: 'select', hasMany: false, options: ['admin', 'user'] }],
      }
      expect(() => applyUsersCollection([single], options, strategy)).toThrow(/hasMany is not true/)
      const missing: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'roles', type: 'select', hasMany: true, options: ['user'] }],
      }
      expect(() => applyUsersCollection([missing], options, strategy)).toThrow(/'admin'/)
      const text: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'roles', type: 'text' }],
      }
      expect(() => applyUsersCollection([text], options, strategy)).toThrow(/not a select/)
    })

    it('adopts a renamed roles field via rolesField remapping', () => {
      const { provider } = createStubProvider()
      const options = wireOptions({
        baseUrl: 'http://auth-link.test',
        roles: ['admin', 'user'],
        defaultRole: 'user',
        rolesField: 'role',
        providers: [provider],
      })
      const strategy = createAuthLinkStrategy(options)
      const existing: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'role', type: 'select', hasMany: true, options: ['admin', 'user'] }],
      }
      const result = applyUsersCollection([existing], options, strategy)
      const users = result[0] as CollectionConfig
      const role = users.fields.find((field) => fieldName(field) === 'role') as Record<
        string,
        unknown
      >
      expect(role.required).toBe(true)
      expect(typeof (role.access as { create?: unknown }).create).toBe('function')
    })
  })

  it('never mutates its input', () => {
    const { options, strategy } = wired()
    const existing: CollectionConfig = { slug: 'users', fields: [] }
    const before = JSON.stringify(existing)
    applyUsersCollection([existing], options, strategy)
    expect(JSON.stringify(existing)).toBe(before)
  })
})
