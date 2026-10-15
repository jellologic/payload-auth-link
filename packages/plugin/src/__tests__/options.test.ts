import {
  isSilentLogger,
  nullLogger,
  InvalidConfigError,
  UnsupportedCapabilityError,
  type LinkingPolicy,
  type SessionChannel,
} from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import { wireOptions, type AuthLinkPluginOptions } from '../options.js'
import { createStubProvider, stubCookieName } from './stub-provider.js'

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

describe('wireOptions', () => {
  it('wires valid options with defaults', () => {
    const wired = wireOptions(options())
    expect(wired.config.map.usersCollection).toBe('users')
    expect(wired.config.map.emailField).toBe('email')
    expect(wired.config.defaultRole).toBe('user')
    expect(wired.registry.ids()).toHaveLength(1)
    expect(wired.depth).toBe(0)
  })

  it('defaults the logger to the console logger and onAudit to null', () => {
    const wired = wireOptions(options())
    // Refusals and audit events must be audible without configuration.
    expect(isSilentLogger(wired.logger)).toBe(false)
    expect(wired.onAudit).toBeNull()
    const opted = wireOptions(options({ logger: nullLogger(), onAudit: () => undefined }))
    expect(isSilentLogger(opted.logger)).toBe(true)
    expect(opted.onAudit).not.toBeNull()
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
    // ARCH-11: the deprecated secret is accepted and ignored, never validated.
    expect(() => wireOptions(options({ secret: 'short' }))).not.toThrow()
    expect(wireOptions(options({ secret: 'short' })).config).not.toHaveProperty('secret')
    expect(() => wireOptions(options({ defaultRole: 'ghost' }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ providers: [] }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ queryDepth: -1 }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ queryDepth: 1.5 }))).toThrow(InvalidConfigError)
  })

  it('defaults to the verified-email linking policy (PORT-3)', () => {
    expect(wireOptions(options()).linkingPolicy).toEqual({ kind: 'verified-email' })
    expect(
      wireOptions(options({ linkingPolicy: { kind: 'verified-email' } })).linkingPolicy
    ).toEqual({ kind: 'verified-email' })
  })

  it('gates the phone linking policy on the phone capability first (PORT-2/PORT-3)', () => {
    // The stub provider declares no capabilities: wiring must refuse
    // with UnsupportedCapabilityError before anything else.
    let caught: unknown
    try {
      wireOptions(options({ linkingPolicy: { kind: 'verified-email-or-phone' } }))
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(UnsupportedCapabilityError)
    if (caught instanceof UnsupportedCapabilityError) {
      expect(caught.capability).toBe('phone')
    }
  })

  it('with a phone-capable provider, wires the phone linking policy (CAP-9)', () => {
    const { provider } = createStubProvider()
    const phoneCapable = { ...provider, capabilities: new Set(['phone' as const]) }
    const wired = wireOptions(
      options({
        providers: [phoneCapable],
        linkingPolicy: { kind: 'verified-email-or-phone' },
      })
    )
    expect(wired.linkingPolicy).toEqual({ kind: 'verified-email-or-phone' })
    expect(wired.userFields.phoneField).toBe('phone')
  })

  it('gates requireMfaForRoles on the mfa capability and known roles (CAP-6)', () => {
    const { provider } = createStubProvider()
    let caught: unknown
    try {
      wireOptions(options({ policies: { requireMfaForRoles: ['admin'] } }))
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(UnsupportedCapabilityError)
    if (caught instanceof UnsupportedCapabilityError) {
      expect(caught.capability).toBe('mfa')
    }
    const mfaCapable = { ...provider, capabilities: new Set(['mfa' as const]) }
    expect(
      wireOptions(options({ providers: [mfaCapable], policies: { requireMfaForRoles: ['admin'] } }))
        .requireMfaForRoles
    ).toEqual(['admin'])
    expect(() =>
      wireOptions(
        options({ providers: [mfaCapable], policies: { requireMfaForRoles: ['superuser'] } })
      )
    ).toThrow(InvalidConfigError)
  })

  it('validates governance field names and organization wiring (CAP-7/9/11)', () => {
    expect(() => wireOptions(options({ phoneField: 'roles' }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ suspendedUntilField: '' }))).toThrow(InvalidConfigError)
    expect(wireOptions(options()).organizations).toBeNull()
    const wired = wireOptions(options({ organizations: { enabled: true } }))
    expect(wired.organizations).toMatchObject({
      organizationsCollection: 'organizations',
      membershipsCollection: 'memberships',
      orgRoles: ['owner', 'admin', 'member'],
    })
    expect(() =>
      wireOptions(options({ organizations: { enabled: true, organizationsCollection: 'users' } }))
    ).toThrow(InvalidConfigError)
  })

  it('fails fast on a malformed linking policy (PORT-3)', () => {
    const malformed = { kind: 'verified-phone' } as unknown as LinkingPolicy
    expect(() => wireOptions(options({ linkingPolicy: malformed }))).toThrow(InvalidConfigError)
  })

  it("defaults admitChannels to ['cookie'] (CAP-13a)", () => {
    expect(wireOptions(options()).admitChannels).toEqual(['cookie'])
    expect(wireOptions(options({ admitChannels: ['cookie', 'bearer'] })).admitChannels).toEqual([
      'cookie',
      'bearer',
    ])
  })

  it('fails fast on empty, duplicate, or unknown admitChannels (CAP-13a)', () => {
    expect(() => wireOptions(options({ admitChannels: [] }))).toThrow(InvalidConfigError)
    expect(() => wireOptions(options({ admitChannels: ['cookie', 'cookie'] }))).toThrow(
      InvalidConfigError
    )
    const bogus = 'header' as unknown as SessionChannel
    expect(() => wireOptions(options({ admitChannels: [bogus] }))).toThrow(InvalidConfigError)
  })

  it('fails fast on duplicate provider ids', () => {
    const first = createStubProvider().provider
    const second = createStubProvider().provider
    expect(() => wireOptions(options({ providers: [first, second] }))).toThrow(/already registered/)
  })

  describe('legacySessions cross-check (issue #72)', () => {
    const pluginWindow = { until: '2099-01-01T00:00:00.000Z', cookieNames: ['bl.session_token'] }

    it('accepts the option when the engine declares the identical window', () => {
      const { provider } = createStubProvider({ legacySessions: pluginWindow })
      const wired = wireOptions(options({ providers: [provider], legacySessions: pluginWindow }))
      expect(wired.legacySessions).toEqual(pluginWindow)
    })

    it('accepts the same window written in a non-canonical form (instant + trimmed-name comparison)', () => {
      // The engine port carries the host's raw strings; the plugin
      // option is normalized. `'…00:00Z'` and `'…00:00.000Z'` are the
      // same instant, and a stray space in a cookie name is not a
      // disagreement.
      const { provider } = createStubProvider({
        legacySessions: { until: '2099-01-01T00:00:00Z', cookieNames: [' bl.session_token '] },
      })
      const wired = wireOptions(options({ providers: [provider], legacySessions: pluginWindow }))
      expect(wired.legacySessions).toEqual(pluginWindow)
    })

    it('accepts engine-only configuration without the plugin option', () => {
      const { provider } = createStubProvider({ legacySessions: pluginWindow })
      const wired = wireOptions(options({ providers: [provider] }))
      expect(wired.legacySessions).toBeNull()
    })

    it('rejects the option when no engine declares a window (the plugin cannot enable coexistence)', () => {
      const { provider } = createStubProvider()
      expect(() =>
        wireOptions(options({ providers: [provider], legacySessions: pluginWindow }))
      ).toThrow(/no provider engine declares a coexistence window/)
    })

    it('rejects a disagreeing engine window', () => {
      const { provider } = createStubProvider({
        legacySessions: { until: '2020-01-01T00:00:00.000Z', cookieNames: ['bl.session_token'] },
      })
      expect(() =>
        wireOptions(options({ providers: [provider], legacySessions: pluginWindow }))
      ).toThrow(/disagrees with the plugin option/)
    })

    it('rejects a legacy cookie name colliding with a current session cookie name', () => {
      // The engine window matches the plugin option (so the
      // disagreement check passes) but its cookie name IS the stub's
      // current session cookie.
      const colliding = {
        until: pluginWindow.until,
        cookieNames: [stubCookieName],
      }
      const { provider } = createStubProvider({ legacySessions: colliding })
      expect(() =>
        wireOptions(options({ providers: [provider], legacySessions: colliding }))
      ).toThrow(/also a current session cookie name/)
    })
  })
})
