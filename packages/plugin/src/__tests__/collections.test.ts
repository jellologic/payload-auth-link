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
    expect(users?.fields.map((field) => fieldName(field))).toEqual(['roles', 'identities'])
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

  it('never mutates its input', () => {
    const { options, strategy } = wired()
    const existing: CollectionConfig = { slug: 'users', fields: [] }
    const before = JSON.stringify(existing)
    applyUsersCollection([existing], options, strategy)
    expect(JSON.stringify(existing)).toBe(before)
  })
})
