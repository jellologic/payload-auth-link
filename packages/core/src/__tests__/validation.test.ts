import { describe, expect, it } from 'vitest'
import { InvalidCollectionMapError, InvalidConfigError } from '../errors.js'
import { parseCollectionMap, validateStartupConfig, type CollectionMap } from '../validation.js'

const validMap: CollectionMap = {
  usersCollection: 'users',
  emailField: 'email',
  rolesField: 'roles',
  identitiesField: 'identities',
}

function validConfig() {
  return {
    baseUrl: 'http://localhost:3100',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: ['better-auth'],
    map: validMap,
  }
}

describe('parseCollectionMap', () => {
  it('accepts a complete map', () => {
    const result = parseCollectionMap(validMap)
    expect(result.isOk()).toBe(true)
  })

  it('rejects unknown keys (strict, no silent extras)', () => {
    const result = parseCollectionMap({ ...validMap, extra: 'nope' })
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(InvalidCollectionMapError)
    }
  })

  it('rejects missing and empty slugs', () => {
    expect(parseCollectionMap({ ...validMap, usersCollection: '' }).isErr()).toBe(true)
    expect(
      parseCollectionMap({
        usersCollection: 'users',
        emailField: 'email',
        identitiesField: 'identities',
      }).isErr()
    ).toBe(true)
  })
})

describe('validateStartupConfig', () => {
  it('accepts a valid config and brands roles', () => {
    const result = validateStartupConfig(validConfig())
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value.defaultRole).toBe('user')
      expect(result.value.providers).toEqual(['better-auth'])
    }
  })

  it('rejects bad urls, unknown keys (the removed secret), and empty lists', () => {
    expect(validateStartupConfig({ ...validConfig(), baseUrl: 'nope' }).isErr()).toBe(true)
    // ARCH-11: the dead secret is gone from the contract (strict schema).
    expect(validateStartupConfig({ ...validConfig(), secret: 'x'.repeat(32) }).isErr()).toBe(true)
    expect(validateStartupConfig({ ...validConfig(), roles: [] }).isErr()).toBe(true)
    expect(validateStartupConfig({ ...validConfig(), providers: [] }).isErr()).toBe(true)
  })

  it('rejects a defaultRole outside roles', () => {
    const result = validateStartupConfig({ ...validConfig(), defaultRole: 'ghost' })
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(InvalidConfigError)
      expect(result.error.message).toContain('defaultRole must be one of roles')
    }
  })
})
