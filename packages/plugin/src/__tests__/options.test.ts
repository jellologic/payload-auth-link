import { InvalidConfigError } from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

function options(overrides?: Partial<AuthLinkPluginOptions>): AuthLinkPluginOptions {
  const { provider } = createStubProvider()
  return {
    baseUrl: 'http://auth-link.test',
    secret: 'x'.repeat(32),
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [provider],
    ...overrides,
  }
}

describe('wireOptions', () => {
  it('wires valid options with defaults', () => {
    const wired = wireOptions(options())
    expect(wired.config.map.usersCollection).toBe('users')
    expect(wired.config.map.emailField).toBe('email')
    expect(wired.config.defaultRole).toBe('user')
    expect(wired.registry.ids()).toHaveLength(1)
    expect(wired.depth).toBe(0)
  })

  it('honors custom map names, ports, and depth', () => {
    const wired = wireOptions(
      options({
        usersCollection: 'members',
        emailField: 'primaryEmail',
        rolesField: 'accessRoles',
        identitiesField: 'linkedAccounts',
        queryDepth: 2,
      })
    )
    expect(wired.config.map.usersCollection).toBe('members')
    expect(wired.config.map.emailField).toBe('primaryEmail')
    expect(wired.config.map.rolesField).toBe('accessRoles')
    expect(wired.config.map.identitiesField).toBe('linkedAccounts')
    expect(wired.depth).toBe(2)
  })

  it('fails fast on invalid config', () => {
    expect(() => wireOptions(options({ baseUrl: 'nope' }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ secret: 'short' }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ defaultRole: 'ghost' }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ providers: [] }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ queryDepth: -1 }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ queryDepth: 1.5 }))).toThrow(InvalidConfigError)
  })

  it('fails fast on duplicate provider ids', () => {
    const first = createStubProvider().provider
    const second = createStubProvider().provider
    expect(() => wireOptions(options({ providers: [first, second] }))).toThrow(/already registered/)
  })
})
