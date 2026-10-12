import { InvalidConfigError } from '@payload-auth-link/core'
import type { Config } from 'payload'
import { describe, expect, it } from 'vitest'
import { authLink, pluginSlug, strategyName } from '../index.js'
import type { AuthLinkPluginOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

function options(overrides?: Partial<AuthLinkPluginOptions>): AuthLinkPluginOptions {
  const { provider } = createStubProvider()
  return {
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [provider],
    ...overrides,
  }
}

describe('plugin entrypoint', () => {
  it('returns a plain version-agnostic Plugin function with slug and options', () => {
    const plugin = authLink(options())
    expect(pluginSlug).toBe('payload-auth-link')
    expect(strategyName).toBe('auth-link')
    expect(plugin.slug).toBe(pluginSlug)
    expect(plugin.options).toMatchObject({ baseUrl: 'http://auth-link.test' })
  })

  it('applies collections and endpoints to a bare config on either Payload line', async () => {
    const plugin = authLink(options())
    // A plain function taking a config: the exact `Plugin` shape on both
    // v3 and v4, with no dependence on `definePlugin` argument shape.
    const out = await plugin({ collections: [], endpoints: [] } as unknown as Config)
    expect(out.collections?.some((collection) => collection.slug === 'users')).toBe(true)
    expect(out.endpoints?.some((endpoint) => endpoint.path === '/auth-link/session')).toBe(true)
  })

  it('fails fast at factory call time on invalid options', () => {
    expect(() => authLink(options({ providers: [] }))).toThrow(InvalidConfigError)
  })
})
