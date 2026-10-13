import { describe, expect, it } from 'vitest'
import {
  DuplicateProviderError,
  InvalidConfigError,
  InvalidProviderIdError,
  UnknownProviderError,
  UnsupportedCapabilityError,
} from '../errors.js'
import {
  assertCapabilities,
  defineProviderId,
  defineSessionId,
  defineUserId,
  type IdentityProviderPort,
} from '../ports.js'
import { createProviderRegistry } from '../registry.js'
import { okAsync } from 'neverthrow'

function stubProvider(
  id: string,
  sessionCookieNames: readonly string[] = []
): IdentityProviderPort {
  return {
    id: defineProviderId(id),
    sessionCookieNames,
    capabilities: new Set(),
    getSession: () => okAsync(null),
    revokeSession: () => okAsync(undefined),
  }
}

describe('defineProviderId', () => {
  it('brands valid ids', () => {
    expect(defineProviderId('custom-idp')).toBe('custom-idp')
  })

  it('throws fail-fast on invalid input', () => {
    expect(() => defineProviderId('')).toThrow(InvalidProviderIdError)
    expect(() => defineProviderId('Has Caps')).toThrow(InvalidProviderIdError)
  })
})

describe('defineUserId / defineSessionId', () => {
  it('brands non-empty ids', () => {
    expect(defineUserId('1')).toBe('1')
    expect(defineSessionId('s')).toBe('s')
  })

  it('throws on empty ids', () => {
    expect(() => defineUserId('')).toThrow('must not be empty')
    expect(() => defineSessionId('')).toThrow('must not be empty')
  })
})

describe('assertCapabilities (PORT-2)', () => {
  it('passes when every required capability is declared (or none required)', () => {
    const provider = { ...stubProvider('capable'), capabilities: new Set(['phone' as const]) }
    expect(() => assertCapabilities(provider, ['phone'])).not.toThrow()
    expect(() => assertCapabilities(provider, [])).not.toThrow()
    expect(() => assertCapabilities(stubProvider('bare'), [])).not.toThrow()
  })

  it('throws UnsupportedCapabilityError naming provider and capability', () => {
    const provider = stubProvider('bare')
    let caught: unknown
    try {
      assertCapabilities(provider, ['phone'])
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(UnsupportedCapabilityError)
    if (caught instanceof UnsupportedCapabilityError) {
      expect(caught.providerId).toBe('bare')
      expect(caught.capability).toBe('phone')
    }
  })
})

describe('createProviderRegistry', () => {
  it('registers and resolves providers', () => {
    const registry = createProviderRegistry()
    const provider = stubProvider('better-auth')
    expect(registry.register(provider).isOk()).toBe(true)
    expect(registry.require(provider.id).isOk()).toBe(true)
    expect(registry.ids()).toEqual([provider.id])
  })

  it('rejects duplicate registration', () => {
    const registry = createProviderRegistry()
    expect(registry.register(stubProvider('better-auth')).isOk()).toBe(true)
    const result = registry.register(stubProvider('better-auth'))
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(DuplicateProviderError)
    }
  })

  it('fails fast at wiring on illegal session cookie names (TYP-8)', () => {
    for (const bad of ['', 'has space', 'semi;colon', 'a=b', 'crlf\r\n']) {
      const registry = createProviderRegistry()
      expect(() => registry.register(stubProvider('bad', ['ok_name', bad]))).toThrow(
        InvalidConfigError
      )
      expect(registry.ids()).toEqual([])
    }
    const registry = createProviderRegistry()
    expect(registry.register(stubProvider('good', ['__Secure-a.session_token'])).isOk()).toBe(true)
  })

  it('fails fast at wiring on illegal logout cookie names too (CAP-8a)', () => {
    const registry = createProviderRegistry()
    expect(() =>
      registry.register({
        ...stubProvider('bad-logout', ['ok_name']),
        logoutCookieNames: ['semi;colon'],
      })
    ).toThrow(InvalidConfigError)
    expect(registry.ids()).toEqual([])
  })

  it('reports unknown providers', () => {
    const registry = createProviderRegistry()
    const result = registry.require(defineProviderId('missing'))
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(UnknownProviderError)
    }
  })
})
