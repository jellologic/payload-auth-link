import {
  InvalidConfigError,
  readInstalledVersion,
  UnsupportedVersionError,
  wellKnownProviderIds,
  type LoggerPort,
} from '@payload-auth-link/core'
import { admin } from 'better-auth/plugins'
import { magicLink } from 'better-auth/plugins/magic-link'
import { organization } from 'better-auth/plugins/organization'
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { defaultBetterAuthSlugs } from '../collections.js'
import { assertBetterAuthVersion, createBetterAuthEngine } from '../engine.js'
import { UnsupportedSchemaError } from '../errors.js'

const getPayload = (): Promise<Payload> => Promise.reject(new Error('no Payload in unit test'))

function spyLogger(): { logger: LoggerPort; warn: ReturnType<typeof vi.fn> } {
  const warn = vi.fn()
  const logger: LoggerPort = {
    debug: vi.fn(),
    info: vi.fn(),
    warn,
    error: vi.fn(),
    child: () => logger,
  }
  return { logger, warn }
}

function warnedSettings(warn: ReturnType<typeof vi.fn>): string {
  return warn.mock.calls.map((call) => String(call[0])).join('\n')
}

describe('better-auth version assertion (Phase 1)', () => {
  it('throws a typed, actionable error outside the validated band', () => {
    // 1.6.33 is the known-bad build (modelKey); 1.8.0 is an
    // unvalidated minor — satellites will force it someday (B12).
    for (const version of ['1.6.33', '1.8.0', '2.0.0']) {
      expect(() => assertBetterAuthVersion(version, spyLogger().logger)).toThrow(
        UnsupportedVersionError
      )
    }
  })

  it('accepts the validated 1.7 line', () => {
    for (const version of ['1.7.6', '1.7.7']) {
      expect(() => assertBetterAuthVersion(version, spyLogger().logger)).not.toThrow()
    }
  })

  it('warns instead of guessing when the manifest is unreadable', () => {
    const { logger, warn } = spyLogger()
    expect(() => assertBetterAuthVersion(null, logger)).not.toThrow()
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0]?.[0])).toContain('skipping the supported-version assertion')
  })

  it('passes for the actually-installed better-auth (self-test of the band)', () => {
    const installed = readInstalledVersion('better-auth', import.meta.url)
    expect(installed).not.toBeNull()
    expect(() => assertBetterAuthVersion(installed, spyLogger().logger)).not.toThrow()
  })
})

describe('createBetterAuthEngine', () => {
  it('requires email verification unless explicitly opted out', () => {
    const secured = createBetterAuthEngine({
      getPayload,
      options: { emailAndPassword: { enabled: true } },
    })
    expect(secured.auth.options.emailAndPassword?.requireEmailVerification).toBe(true)

    const optedOut = createBetterAuthEngine({
      getPayload,
      options: { emailAndPassword: { enabled: true, requireEmailVerification: false } },
    })
    expect(optedOut.auth.options.emailAndPassword?.requireEmailVerification).toBe(false)

    const absent = createBetterAuthEngine({ getPayload, options: {} })
    expect(absent.auth.options.emailAndPassword).toBeUndefined()
  })

  it('revokes sessions on password reset by default, overridable (CAP-14)', () => {
    const secured = createBetterAuthEngine({
      getPayload,
      options: { emailAndPassword: { enabled: true } },
    })
    expect(secured.auth.options.emailAndPassword?.revokeSessionsOnPasswordReset).toBe(true)
    const optedOut = createBetterAuthEngine({
      getPayload,
      options: { emailAndPassword: { enabled: true, revokeSessionsOnPasswordReset: false } },
    })
    expect(optedOut.auth.options.emailAndPassword?.revokeSessionsOnPasswordReset).toBe(false)
  })

  it('translates database hooks into identity events, preserving builder hooks (CAP-14)', async () => {
    const builderAfter = vi.fn(() => Promise.resolve())
    const engine = createBetterAuthEngine({
      getPayload,
      options: {
        emailAndPassword: { enabled: true },
        databaseHooks: { user: { update: { after: builderAfter } } },
      },
    })
    const seen: string[] = []
    const unsubscribe = engine.provider.onIdentityEvent?.((event) => {
      seen.push(event.type)
      return Promise.resolve()
    })
    expect(engine.provider.onIdentityEvent).toBeTypeOf('function')
    const user = {
      id: 'ba-9',
      email: 'new@example.com',
      emailVerified: true,
      name: 'N',
      image: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    await engine.auth.options.databaseHooks?.user?.update?.after?.(user, null)
    expect(builderAfter).toHaveBeenCalledTimes(1)
    expect(seen).toEqual(['email-changed'])
    await engine.auth.options.databaseHooks?.user?.delete?.after?.(user, null)
    expect(seen).toEqual(['email-changed', 'user-deleted'])
    unsubscribe?.()
    await engine.auth.options.databaseHooks?.user?.delete?.after?.(user, null)
    expect(seen).toHaveLength(2)
  })

  it('passes the builder plugin list through verbatim, appending nothing', () => {
    const marker = magicLink({ sendMagicLink: () => Promise.resolve() })
    const engine = createBetterAuthEngine({ getPayload, options: { plugins: [marker] } })
    // Same reference in, same reference out: no copies, no extras.
    expect(engine.auth.options.plugins).toHaveLength(1)
    expect(engine.auth.options.plugins?.[0]).toBe(marker)
  })

  it('leaves an absent plugin list absent', () => {
    const engine = createBetterAuthEngine({ getPayload, options: {} })
    expect(engine.auth.options.plugins ?? []).toHaveLength(0)
  })

  it('declares impersonation only when the admin plugin is in the plugin list (PORT-2)', () => {
    const withoutAdmin = createBetterAuthEngine({ getPayload, options: {} })
    expect(withoutAdmin.provider.capabilities.has('impersonation')).toBe(false)
    const markerOnly = createBetterAuthEngine({
      getPayload,
      options: { plugins: [magicLink({ sendMagicLink: () => Promise.resolve() })] },
    })
    expect(markerOnly.provider.capabilities.has('impersonation')).toBe(false)
    const withAdmin = createBetterAuthEngine({
      getPayload,
      // The admin plugin's fields must be declared for the schema
      // probe at init (mirrors impersonation.test.ts).
      customFields: {
        user: [
          { name: 'role', type: 'text' },
          { name: 'banned', type: 'boolean' },
          { name: 'banReason', type: 'text' },
          { name: 'banExpires', type: 'date' },
        ],
        session: [{ name: 'impersonatedBy', type: 'text' }],
      },
      options: { plugins: [admin()] },
    })
    expect(withAdmin.provider.capabilities).toEqual(
      new Set([
        'impersonation',
        'revoke-user-sessions',
        'server-session-create',
        'server-session-list',
      ])
    )
    // Plugin-derived capabilities (CAP-1..6): magic-link present
    // above declares its capability without claiming impersonation.
    expect(markerOnly.provider.capabilities.has('magic-link')).toBe(true)
    expect(markerOnly.provider.capabilities.has('revoke-user-sessions')).toBe(true)
    expect(markerOnly.provider.capabilities.has('server-session-create')).toBe(true)
    expect(markerOnly.provider.capabilities.has('server-session-list')).toBe(true)
  })

  it('wires the provider, collections, slugs, and cookie names', () => {
    const engine = createBetterAuthEngine({ getPayload, options: {} })
    expect(engine.provider.id).toBe(wellKnownProviderIds.betterAuth)
    expect(engine.provider.sessionCookieNames).toEqual(engine.sessionCookieNames)
    expect(engine.sessionCookieNames).toEqual(['better-auth.session_token'])
    expect(engine.slugs).toEqual(defaultBetterAuthSlugs)
    expect(engine.collections.map((collection) => collection.slug).sort()).toEqual(
      Object.values(defaultBetterAuthSlugs).sort()
    )
    expect(engine.auth.options.database).toBeDefined()
  })

  it('preserves Better Auth option-driven typing through composition', () => {
    const engine = createBetterAuthEngine({
      getPayload,
      options: { plugins: [magicLink({ sendMagicLink: () => Promise.resolve() })] },
    })
    // Compile-asserted: plugin endpoints survive the engine composition.
    expect(typeof engine.auth.api.signInMagicLink).toBe('function')
    expect(typeof engine.auth.api.getSession).toBe('function')
  })

  it('warns (not throws) on trustedProviders without per-provider requireEmailVerification', () => {
    const { logger, warn } = spyLogger()
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        logger,
        options: { account: { accountLinking: { trustedProviders: ['google'] } } },
      })
    ).not.toThrow()
    expect(warn).toHaveBeenCalled()
    expect(warnedSettings(warn)).toContain('trustedProviders')
    expect(warnedSettings(warn)).toContain('google')
    expect(warnedSettings(warn)).toContain('requireEmailVerification')
  })

  it('throws InvalidConfigError for the same config under strictLinking', () => {
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        strictLinking: true,
        options: { account: { accountLinking: { trustedProviders: ['google'] } } },
      })
    ).toThrow(InvalidConfigError)
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        strictLinking: true,
        options: { account: { accountLinking: { trustedProviders: ['google'] } } },
      })
    ).toThrow('trustedProviders')
  })

  it('does not warn when a trusted social provider requires email verification', () => {
    const { logger, warn } = spyLogger()
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        logger,
        strictLinking: true,
        options: {
          socialProviders: {
            google: { clientId: 'id', clientSecret: 'secret', requireEmailVerification: true },
          },
          account: { accountLinking: { trustedProviders: ['google'] } },
        },
      })
    ).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('warns on a dynamic trustedProviders function it cannot verify statically', () => {
    const { logger, warn } = spyLogger()
    createBetterAuthEngine({
      getPayload,
      logger,
      options: { account: { accountLinking: { trustedProviders: () => ['google'] } } },
    })
    expect(warnedSettings(warn)).toContain('trustedProviders')
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        strictLinking: true,
        options: { account: { accountLinking: { trustedProviders: () => ['google'] } } },
      })
    ).toThrow('trustedProviders')
  })

  it('stays silent when linking is disabled or implicit linking is off', () => {
    const { logger, warn } = spyLogger()
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        logger,
        strictLinking: true,
        options: {
          account: { accountLinking: { enabled: false, trustedProviders: ['google'] } },
        },
      })
    ).not.toThrow()
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        logger,
        strictLinking: true,
        options: {
          account: {
            accountLinking: {
              disableImplicitLinking: true,
              trustedProviders: ['google'],
              requireLocalEmailVerified: false,
            },
          },
        },
      })
    ).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('warns on allowDifferentEmails and requireLocalEmailVerified:false, throws under strictLinking', () => {
    const risky = [
      { accountLinking: { allowDifferentEmails: true }, setting: 'allowDifferentEmails' },
      {
        accountLinking: { requireLocalEmailVerified: false },
        setting: 'requireLocalEmailVerified',
      },
    ] as const
    for (const { accountLinking, setting } of risky) {
      const { logger, warn } = spyLogger()
      createBetterAuthEngine({ getPayload, logger, options: { account: { accountLinking } } })
      expect(warnedSettings(warn)).toContain(setting)
      expect(() =>
        createBetterAuthEngine({
          getPayload,
          strictLinking: true,
          options: { account: { accountLinking } },
        })
      ).toThrow(setting)
    }
  })

  it('forces updateUserInfoOnLink off with a warning, and throws under strictLinking', () => {
    const { logger, warn } = spyLogger()
    const engine = createBetterAuthEngine({
      getPayload,
      logger,
      options: { account: { accountLinking: { updateUserInfoOnLink: true } } },
    })
    expect(warnedSettings(warn)).toContain('updateUserInfoOnLink')
    expect(engine.auth.options.account?.accountLinking?.updateUserInfoOnLink).toBe(false)
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        strictLinking: true,
        options: { account: { accountLinking: { updateUserInfoOnLink: true } } },
      })
    ).toThrow('updateUserInfoOnLink')
  })

  it('stays silent for configs without risky linking settings', () => {
    const { logger, warn } = spyLogger()
    createBetterAuthEngine({ getPayload, logger, options: {} })
    createBetterAuthEngine({
      getPayload,
      logger,
      strictLinking: true,
      options: { account: { accountLinking: { trustedProviders: [] } } },
    })
    expect(warn).not.toHaveBeenCalled()
  })

  it('fails loud when a plugin extends a core model (v1 supports core fields only)', async () => {
    const engine = createBetterAuthEngine({
      getPayload,
      options: { plugins: [organization()] },
    })
    // Better Auth defers adapter init, so the failure surfaces on $context.
    await expect(engine.auth.$context).rejects.toBeInstanceOf(UnsupportedSchemaError)
  })
})
