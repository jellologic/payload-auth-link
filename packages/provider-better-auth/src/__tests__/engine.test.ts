import {
  InvalidConfigError,
  readInstalledVersion,
  UnsupportedVersionError,
  wellKnownProviderIds,
  type LoggerPort,
} from '@payload-auth-link/core'
import { authLink } from '@payload-auth-link/plugin'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import type { BetterAuthOptions } from 'better-auth'
import { admin } from 'better-auth/plugins'
import { magicLink } from 'better-auth/plugins/magic-link'
import { organization } from 'better-auth/plugins/organization'
import { buildConfig, getPayload as getPayloadFromPayload, type Payload } from 'payload'
import { beforeAll, describe, expect, it, vi } from 'vitest'
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

  it('passes the builder plugin list through by reference plus the engine plugins', () => {
    const marker = magicLink({ sendMagicLink: () => Promise.resolve() })
    const engine = createBetterAuthEngine({ getPayload, options: { plugins: [marker] } })
    // Same references in, same references out, plus the engine-owned
    // plugins (session provenance and token redaction, no endpoints).
    const ids = (engine.auth.options.plugins as readonly { id?: string }[] | undefined)?.map(
      (plugin) => plugin.id
    )
    expect(engine.auth.options.plugins?.[0]).toBe(marker)
    expect(ids).toEqual([
      'magic-link',
      'payload-auth-link-account-state',
      'payload-auth-link-session-provenance',
      'payload-auth-link-session-token-redaction',
    ])
  })

  it('gives an absent plugin list exactly the engine plugins', () => {
    const engine = createBetterAuthEngine({ getPayload, options: {} })
    expect(engine.auth.options.plugins?.map((plugin) => plugin.id)).toEqual([
      'payload-auth-link-account-state',
      'payload-auth-link-session-provenance',
      'payload-auth-link-session-token-redaction',
    ])
  })

  it('exposeSessionTokens: true leaves the redaction plugin out (issue #113)', () => {
    const engine = createBetterAuthEngine({ getPayload, exposeSessionTokens: true, options: {} })
    expect(engine.auth.options.plugins?.map((plugin) => plugin.id)).toEqual([
      'payload-auth-link-account-state',
      'payload-auth-link-session-provenance',
    ])
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

  it('surfaces magic-link and social-provider facts on the port (issue #157)', () => {
    // Without the plugin and without social providers, both facts are
    // ABSENT — a login view reading them renders no alternative
    // methods.
    const plain = createBetterAuthEngine({ getPayload, options: {} })
    expect(plain.provider.magicLinkEnabled).toBeUndefined()
    expect(plain.provider.socialProviders).toBeUndefined()

    const withMethods = createBetterAuthEngine({
      getPayload,
      options: {
        plugins: [magicLink({ sendMagicLink: () => Promise.resolve() })],
        socialProviders: {
          google: { clientId: 'id', clientSecret: 'secret' },
          github: { clientId: 'id', clientSecret: 'secret' },
        },
      },
    })
    expect(withMethods.provider.magicLinkEnabled).toBe(true)
    // The CONFIGURED ids (the option's object keys), in config order.
    expect(withMethods.provider.socialProviders).toEqual(['google', 'github'])

    // Social providers alone do not flip the magic-link fact.
    const socialOnly = createBetterAuthEngine({
      getPayload,
      options: { socialProviders: { google: { clientId: 'id', clientSecret: 'secret' } } },
    })
    expect(socialOnly.provider.magicLinkEnabled).toBeUndefined()
    expect(socialOnly.provider.socialProviders).toEqual(['google'])
  })

  it('surfaces the adopted collection slugs on the port (GHSA-hfm3)', () => {
    // Without adoption the fact is ABSENT: the engine's own ba-*
    // collections are already unversioned and access-denied.
    const plain = createBetterAuthEngine({ getPayload, options: {} })
    expect(plain.provider.adoptedCollections).toBeUndefined()

    // With a schemaMap, every adopted slug — the plugin hardens
    // exactly these (versioning off, readVersions closed), minus the
    // users slug it governs through withDefaultUserAccess.
    const adopted = createBetterAuthEngine({
      getPayload,
      options: {},
      schemaMap: {
        user: { slug: 'users' },
        session: { slug: 'sessions' },
        verification: { slug: 'verifications' },
        account: { slug: 'accounts' },
      },
    })
    expect(adopted.provider.adoptedCollections).toEqual([
      'users',
      'sessions',
      'verifications',
      'accounts',
    ])

    // Two plugin models cannot share a slug (the adapter refuses that
    // at construction), so no dedupe happens here — the report is the
    // schemaMap's order verbatim.
    const ordered = createBetterAuthEngine({
      getPayload,
      options: {},
      schemaMap: {
        organization: { slug: 'organizations' },
        member: { slug: 'members' },
        session: { slug: 'sessions' },
      },
      customModels: [
        { model: 'organization', fields: [{ name: 'name', type: 'text' }] },
        { model: 'member', fields: [{ name: 'organizationId', type: 'text' }] },
      ],
    })
    expect(ordered.provider.adoptedCollections).toEqual(['organizations', 'members', 'sessions'])
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

  it('a trusted email-password provider is safe only while email verification stays on (#110)', () => {
    const trusted = { account: { accountLinking: { trustedProviders: ['email-password'] } } }
    // emailAndPassword on with the engine's default requirement: safe.
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        strictLinking: true,
        options: { ...trusted, emailAndPassword: { enabled: true } },
      })
    ).not.toThrow()
    // Explicitly switched off: the trusted provider links on its word alone.
    expect(() =>
      createBetterAuthEngine({
        getPayload,
        strictLinking: true,
        options: {
          ...trusted,
          emailAndPassword: { enabled: true, requireEmailVerification: false },
        },
      })
    ).toThrow('email-password')
    // No emailAndPassword block at all: nothing statically proves it.
    expect(() =>
      createBetterAuthEngine({ getPayload, strictLinking: true, options: trusted })
    ).toThrow('email-password')
  })

  it('a trusted social provider without an explicit true requirement is a finding (#110)', () => {
    for (const socialProviders of [
      undefined,
      { google: { clientId: 'id', clientSecret: 'secret' } },
      { google: { clientId: 'id', clientSecret: 'secret', requireEmailVerification: false } },
    ]) {
      expect(() =>
        createBetterAuthEngine({
          getPayload,
          strictLinking: true,
          options: {
            ...(socialProviders === undefined ? {} : { socialProviders }),
            account: { accountLinking: { trustedProviders: ['google'] } },
          },
        })
      ).toThrow('google')
    }
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

/**
 * Issue #156 regression: payload-auth 1.9.4 rewrites the app's OWN
 * `betterAuthOptions.hooks` object in place on every config build, so
 * a SECOND build in the same process stacks its better-call wrappers
 * and every Better Auth endpoint starts answering a
 * `{ headers, response }` envelope — no session anywhere, and the
 * payload-auth strategy then throws on `res.session.userId`. This pins
 * the property payload-auth-link already has: building the engine
 * twice from the SAME options object reference leaves the
 * app-supplied hooks object untouched and both engines' endpoints
 * identical.
 *
 * Real Better Auth on real Payload storage (SQLite in memory) behind a
 * real authLink boot, driven through `auth.handler` and `auth.api`.
 */
describe('issue #156: two engine builds from one options object never stack hooks', () => {
  const ORIGIN = 'http://engine-156.test'
  const SECRET = 'engine-issue-156-secret-0123456789ab'
  const PASSWORD = 'correct-horse-battery'

  const beforePaths: string[] = []
  const afterPaths: string[] = []
  /** The request path a hook context names, defensively extracted:
   * `request` may be absent or its URL relative/unparseable here. */
  function pathOf(context: { readonly request?: { readonly url?: string } | undefined }): string {
    try {
      return new URL(context.request?.url ?? 'http://local.test/').pathname
    } catch {
      return '(unparseable)'
    }
  }
  // The app-supplied hooks object, passed BY REFERENCE into the
  // options — exactly the object payload-auth 1.9.4 wraps in place.
  const hooks: NonNullable<BetterAuthOptions['hooks']> = {
    before: (context) => {
      beforePaths.push(pathOf(context))
      // The PROMISE return is load-bearing: better-auth 1.7's
      // runBeforeHooks does `withSpan(...).catch(...)` on the hook's
      // return, so a synchronous undefined return crashes it.
      // Resolving without a value lets the request continue —
      // payload-auth's stacked wrapper instead RESOLVES the hook with
      // the `{ headers, response }` envelope it received, which Better
      // Auth then treats as the ANSWER — the endpoint never runs.
      return Promise.resolve(undefined)
    },
    after: (context) => {
      afterPaths.push(pathOf(context))
      // Better Auth 1.7's after-hook contract resolves with an object
      // (`{ response }`) — pass the response through unchanged.
      return Promise.resolve({
        response: (context as { context?: { returned?: unknown } }).context?.returned,
      })
    },
  }

  const options: Omit<BetterAuthOptions, 'database'> = {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, requireEmailVerification: false },
    hooks,
  }

  // Function-aware deep snapshot: each function maps to a stable id,
  // so a WRAPPED hook (payload-auth's move) fails the compare where a
  // JSON.stringify snapshot would silently drop it.
  const fnIds = new Map<unknown, number>()
  function snapshot(value: unknown): unknown {
    if (typeof value === 'function') {
      let id = fnIds.get(value)
      if (id === undefined) {
        id = fnIds.size
        fnIds.set(value, id)
      }
      return `<function ${String(id)}>`
    }
    if (value === null || typeof value !== 'object') {
      return value
    }
    if (Array.isArray(value)) {
      return value.map(snapshot)
    }
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, snapshot(entry)])
    )
  }

  // Taken BEFORE any engine build: if a build mutated the options, the
  // final compare against this snapshot fails.
  const snapshotBefore = snapshot(options)

  let payload: Payload | undefined
  const live = (): Payload => {
    if (payload === undefined) {
      throw new Error('Payload not ready')
    }
    return payload
  }

  // ONE input object, shared by BOTH builds (same reference).
  const engineInput = {
    getPayload: (): Promise<Payload> => Promise.resolve(live()),
    options,
  }
  const first = createBetterAuthEngine(engineInput)

  beforeAll(async () => {
    const config = await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      collections: [{ slug: 'users', auth: true, fields: [] }, ...first.collections],
      plugins: [
        authLink({
          baseUrl: ORIGIN,
          roles: ['admin', 'user'],
          defaultRole: 'user',
          providers: [first.provider],
        }),
      ],
    })
    payload = await getPayloadFromPayload({ config })
    await first.auth.$context
  }, 120_000)

  type HandlerOnly = {
    readonly auth: { readonly handler: (request: Request) => Promise<Response> }
  }

  function post(engine: HandlerOnly, path: string, body: unknown): Promise<Response> {
    return engine.auth.handler(
      new Request(`${ORIGIN}/api/auth${path}`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
    )
  }

  function get(engine: HandlerOnly, path: string, cookie: string): Promise<Response> {
    return engine.auth.handler(
      new Request(`${ORIGIN}/api/auth${path}`, { headers: { origin: ORIGIN, cookie } })
    )
  }

  /** The BA session cookie pair a response set (throws when absent). */
  function cookieOf(response: Response): string {
    const name = first.sessionCookieNames[0] ?? ''
    const entry = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))
    if (entry === undefined) {
      throw new Error(`no session cookie set (status ${String(response.status)})`)
    }
    return entry.split(';')[0] ?? ''
  }

  it('keeps every endpoint working and the app hooks object untouched', async () => {
    // The FIRST build: a plain sign-up answers normally.
    const email = 'second-build@engine-156.test'
    const up = await post(first, '/sign-up/email', { name: 'Builds', email, password: PASSWORD })
    expect(up.status).toBe(200)
    const upBody = (await up.json()) as Record<string, unknown>
    expect(upBody).toMatchObject({ user: { email } })
    // The payload-auth 1.9.4 fingerprint is `{"response":{"headers":{}}}`.
    expect(upBody).not.toHaveProperty('response')
    const cookie = cookieOf(up)

    // The SECOND build from the SAME options object — payload-auth's
    // moment of failure. Here it must change nothing.
    const second = createBetterAuthEngine(engineInput)
    await second.auth.$context

    // Sign in through the SECOND engine, then read the session back
    // through its API: a session object, never the envelope.
    const signIn = await post(second, '/sign-in/email', { email, password: PASSWORD })
    expect(signIn.status).toBe(200)
    const signInBody = (await signIn.json()) as Record<string, unknown>
    expect(signInBody).toMatchObject({ user: { email } })
    expect(signInBody).not.toHaveProperty('response')
    const secondCookie = cookieOf(signIn)
    const session = await second.auth.api.getSession({
      headers: new Headers({ cookie: secondCookie }),
    })
    expect(session).not.toBeNull()
    expect(session?.user?.email).toBe(email)
    expect(session?.session?.userId).toEqual(expect.any(String))

    // Sign-up through the SECOND build answers normally too.
    const secondEmail = 'second-build-too@engine-156.test'
    const up2 = await post(second, '/sign-up/email', {
      name: 'Builds Too',
      email: secondEmail,
      password: PASSWORD,
    })
    expect(up2.status).toBe(200)
    const up2Body = (await up2.json()) as Record<string, unknown>
    expect(up2Body).toMatchObject({ user: { email: secondEmail } })
    expect(up2Body).not.toHaveProperty('response')

    // The FIRST engine still serves its cookie after the second build:
    // the second engine's endpoints behave identically to the first's.
    const again = await get(first, '/get-session', cookie)
    expect(again.status).toBe(200)
    expect(await again.json()).toMatchObject({ user: { email } })

    // The app-supplied hooks object was never mutated: the SAME
    // functions by reference (payload-auth replaces `before`/`after`
    // with wrappers), the same deep shape, and the hooks still ran as
    // pass-throughs on the requests above.
    expect(options.hooks?.before).toBe(hooks.before)
    expect(options.hooks?.after).toBe(hooks.after)
    expect(snapshot(options)).toEqual(snapshotBefore)
    expect(beforePaths.length).toBeGreaterThan(0)
    expect(afterPaths.length).toBeGreaterThan(0)
  })
})
