import {
  InvalidConfigError,
  readInstalledVersion,
  UnsupportedVersionError,
  type LoggerPort,
} from '@payload-auth-link/core'
import type { AuthConfig } from '@auth/core'
import Credentials from '@auth/core/providers/credentials'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Payload } from 'payload'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defaultAuthJsSlugs } from '../collections.js'
import {
  anchorRequestOrigin,
  assertAuthJsCoreVersion,
  createAuthJsEngine,
  type AuthJsEngineInput,
} from '../engine.js'

const SECRET = 'authjs-engine-test-secret!!'

describe('@auth/core version assertion (Phase 1)', () => {
  it('throws a typed, actionable error outside the validated band', () => {
    // 0.40.x predates the tested 0.41 line; 0.42.0 is an unvalidated
    // minor that may add Adapter methods (the keyof pin alarms).
    for (const version of ['0.40.0', '0.42.0', '1.0.0']) {
      expect(() => assertAuthJsCoreVersion(version, spyLogger().logger)).toThrow(
        UnsupportedVersionError
      )
    }
  })

  it('accepts the validated 0.41 line', () => {
    for (const version of ['0.41.0', '0.41.3']) {
      expect(() => assertAuthJsCoreVersion(version, spyLogger().logger)).not.toThrow()
    }
  })

  it('warns instead of guessing when the manifest is unreadable', () => {
    const { logger, warn } = spyLogger()
    expect(() => assertAuthJsCoreVersion(null, logger)).not.toThrow()
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0]?.[0])).toContain('skipping the supported-version assertion')
  })

  it('passes for the actually-installed @auth/core (self-test of the band)', () => {
    const installed = readInstalledVersion('@auth/core', import.meta.url)
    expect(installed).not.toBeNull()
    expect(() => assertAuthJsCoreVersion(installed, spyLogger().logger)).not.toThrow()
  })
})

function credentialsProvider(): AuthConfig['providers'][number] {
  return Credentials({
    credentials: {
      email: { label: 'Email', type: 'email' },
      password: { label: 'Password', type: 'password' },
    },
    authorize: () => Promise.resolve(null),
  })
}

function fakePayload(): {
  payload: Payload
  find: ReturnType<typeof vi.fn>
  remove: ReturnType<typeof vi.fn>
} {
  const find = vi.fn(() => Promise.resolve({ docs: [], totalDocs: 0 }))
  const remove = vi.fn(() => Promise.resolve({ docs: [], errors: [] }))
  return { payload: { find, delete: remove } as unknown as Payload, find, remove }
}

function baseInput(overrides: Partial<AuthJsEngineInput> = {}): AuthJsEngineInput {
  const { payload } = fakePayload()
  return {
    getPayload: () => Promise.resolve(payload),
    options: { providers: [], secret: SECRET },
    ...overrides,
  }
}

afterEach(() => {
  vi.unstubAllEnvs()
})

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

function dangerousProvider(): AuthConfig['providers'][number] {
  return {
    id: 'google',
    name: 'Google',
    type: 'oidc',
    allowDangerousEmailAccountLinking: true,
  } as unknown as AuthConfig['providers'][number]
}

describe('engine risky linking validation (CAP-12)', () => {
  it('warns (not throws) on allowDangerousEmailAccountLinking by default', () => {
    const { logger, warn } = spyLogger()
    expect(() =>
      createAuthJsEngine(
        baseInput({ logger, options: { providers: [dangerousProvider()], secret: SECRET } })
      )
    ).not.toThrow()
    expect(warn).toHaveBeenCalledTimes(1)
    const [message, fields] = warn.mock.calls[0] as [string, Record<string, unknown>]
    expect(message).toContain('allowDangerousEmailAccountLinking')
    expect(message).toContain('google')
    expect(fields).toMatchObject({ setting: 'allowDangerousEmailAccountLinking' })
  })

  it('throws InvalidConfigError on allowDangerousEmailAccountLinking under strictLinking', () => {
    expect(() =>
      createAuthJsEngine(
        baseInput({
          strictLinking: true,
          options: { providers: [dangerousProvider()], secret: SECRET },
        })
      )
    ).toThrow(InvalidConfigError)
    expect(() =>
      createAuthJsEngine(
        baseInput({
          strictLinking: true,
          options: { providers: [dangerousProvider()], secret: SECRET },
        })
      )
    ).toThrow('allowDangerousEmailAccountLinking')
  })

  it('warns through factory-wrapped dangerous providers', () => {
    const { logger, warn } = spyLogger()
    const factory = (() => ({
      id: 'google',
      name: 'Google',
      type: 'oidc',
      allowDangerousEmailAccountLinking: true,
    })) as unknown as AuthConfig['providers'][number]
    createAuthJsEngine(baseInput({ logger, options: { providers: [factory], secret: SECRET } }))
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('stays silent without dangerous linking, even under strictLinking', () => {
    const { logger, warn } = spyLogger()
    const safe = {
      id: 'google',
      name: 'Google',
      type: 'oidc',
    } as unknown as AuthConfig['providers'][number]
    expect(() =>
      createAuthJsEngine(
        baseInput({ logger, strictLinking: true, options: { providers: [safe], secret: SECRET } })
      )
    ).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('still reports a dangerous provider that has no id, by placeholder', () => {
    const anonymous = {
      name: 'Anonymous',
      type: 'oidc',
      allowDangerousEmailAccountLinking: true,
    } as unknown as AuthConfig['providers'][number]
    const { logger, warn } = spyLogger()
    createAuthJsEngine(baseInput({ logger, options: { providers: [anonymous], secret: SECRET } }))
    expect(warn).toHaveBeenCalledTimes(1)
    const [message, fields] = warn.mock.calls[0] as [string, Record<string, unknown>]
    expect(message).toContain('"<unknown provider id>"')
    expect(fields).toMatchObject({ providerId: '<unknown provider id>' })
    expect(() =>
      createAuthJsEngine(
        baseInput({ strictLinking: true, options: { providers: [anonymous], secret: SECRET } })
      )
    ).toThrow('"<unknown provider id>"')
  })
})

describe('engine fail-fasts', () => {
  it('requires a secret from options or AUTH_SECRET', () => {
    vi.stubEnv('AUTH_SECRET', '')
    delete process.env.AUTH_SECRET
    expect(() => createAuthJsEngine(baseInput({ options: { providers: [] } }))).toThrow(
      InvalidConfigError
    )
    expect(() => createAuthJsEngine(baseInput({ options: { providers: [] } }))).toThrow(
      'options.secret or the AUTH_SECRET environment variable'
    )
    vi.stubEnv('AUTH_SECRET', SECRET)
    expect(() => createAuthJsEngine(baseInput({ options: { providers: [] } }))).not.toThrow()
  })

  it('rejects credentials with the database strategy and demands explicit jwt', () => {
    expect(() =>
      createAuthJsEngine(
        baseInput({ options: { providers: [credentialsProvider()], secret: SECRET } })
      )
    ).toThrow('credentials require explicit session: { strategy: "jwt" }')

    expect(() =>
      createAuthJsEngine(
        baseInput({
          options: {
            providers: [credentialsProvider()],
            secret: SECRET,
            session: { strategy: 'jwt' },
          },
        })
      )
    ).not.toThrow()

    expect(() =>
      createAuthJsEngine(baseInput({ options: { providers: [], secret: SECRET } }))
    ).not.toThrow()
  })

  it('sees through factory-wrapped providers the way Auth.js does', () => {
    const factory = (() => credentialsProvider()) as unknown as AuthConfig['providers'][number]
    // Auth.js calls factories with `{}`; the engine does the same to
    // inspect the type, so wrapped credentials fail fast here too.
    expect(() =>
      createAuthJsEngine(baseInput({ options: { providers: [factory], secret: SECRET } }))
    ).toThrow('credentials require explicit session: { strategy: "jwt" }')
    expect(() =>
      createAuthJsEngine(
        baseInput({
          options: { providers: [factory], secret: SECRET, session: { strategy: 'jwt' } },
        })
      )
    ).not.toThrow()
  })

  it('fails fast when trustProviderEmailVerification meets allowDangerousEmailAccountLinking', () => {
    const dangerous = {
      id: 'google',
      name: 'Google',
      type: 'oidc',
      allowDangerousEmailAccountLinking: true,
    } as unknown as AuthConfig['providers'][number]
    expect(() =>
      createAuthJsEngine(
        baseInput({
          trustProviderEmailVerification: ['google'],
          options: { providers: [dangerous], secret: SECRET },
        })
      )
    ).toThrow(InvalidConfigError)
    expect(() =>
      createAuthJsEngine(
        baseInput({
          trustProviderEmailVerification: ['google'],
          options: { providers: [dangerous], secret: SECRET },
        })
      )
    ).toThrow('allowDangerousEmailAccountLinking')

    // Dangerous linking on a provider that is NOT trusted stays allowed.
    expect(() =>
      createAuthJsEngine(
        baseInput({
          trustProviderEmailVerification: ['acme-oidc'],
          options: { providers: [dangerous], secret: SECRET },
        })
      )
    ).not.toThrow()
    // Trusting a provider without dangerous linking is the intended use.
    const safe = {
      id: 'google',
      name: 'Google',
      type: 'oidc',
    } as unknown as AuthConfig['providers'][number]
    expect(() =>
      createAuthJsEngine(
        baseInput({
          trustProviderEmailVerification: ['google'],
          options: { providers: [safe], secret: SECRET },
        })
      )
    ).not.toThrow()
  })

  it('sees dangerous linking through factory-wrapped providers', () => {
    const factory = (() => ({
      id: 'google',
      name: 'Google',
      type: 'oidc',
      allowDangerousEmailAccountLinking: true,
    })) as unknown as AuthConfig['providers'][number]
    expect(() =>
      createAuthJsEngine(
        baseInput({
          trustProviderEmailVerification: ['google'],
          options: { providers: [factory], secret: SECRET },
        })
      )
    ).toThrow('allowDangerousEmailAccountLinking')
  })

  it('rejects empty trustProviderEmailVerification entries', () => {
    expect(() => createAuthJsEngine(baseInput({ trustProviderEmailVerification: [''] }))).toThrow(
      InvalidConfigError
    )
  })

  it('fails fast when a provider factory throws on inspection', () => {
    const exploding = (() => {
      throw new Error('needs options')
    }) as unknown as AuthConfig['providers'][number]
    // Auth.js would throw the same way on first request; the engine
    // surfaces it at wiring time with the fix attached.
    expect(() =>
      createAuthJsEngine(baseInput({ options: { providers: [exploding], secret: SECRET } }))
    ).toThrow('provider factory threw')
  })

  it('names a non-Error factory throw instead of dropping it', () => {
    const exploding = (() => {
      // A factory may throw anything; the wiring error must still say what.
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      throw 'factory exploded'
    }) as unknown as AuthConfig['providers'][number]
    expect(() =>
      createAuthJsEngine(baseInput({ options: { providers: [exploding], secret: SECRET } }))
    ).toThrow(/provider factory threw.*factory exploded/)
  })
})

describe('engine composition', () => {
  it('defaults basePath and trustHost without clobbering builder values', () => {
    const engine = createAuthJsEngine(baseInput())
    expect(engine.config.basePath).toBe('/api/authjs')
    // Raw `@auth/core` answers every request with `UntrustedHost` unless
    // `trustHost` is truthy (its `assertConfig` has no `AUTH_URL` rescue —
    // `Auth()` never runs `setEnvDefaults`), so `false` is not a usable
    // default at this layer; host strictness comes from origin anchoring
    // in `handleRequest` instead (see below).
    expect(engine.config.trustHost).toBe(true)

    const custom = createAuthJsEngine(
      baseInput({ options: { providers: [], secret: SECRET, basePath: '/sso' } })
    )
    expect(custom.config.basePath).toBe('/sso')
    expect(custom.config.trustHost).toBe(true)
  })

  it('passes through an explicit trustHost value', () => {
    const engine = createAuthJsEngine(
      baseInput({ options: { providers: [], secret: SECRET, trustHost: true } })
    )
    expect(engine.config.trustHost).toBe(true)
  })

  it('defaults credentials deployments to a short session maxAge', () => {
    const engine = createAuthJsEngine(
      baseInput({
        options: {
          providers: [credentialsProvider()],
          secret: SECRET,
          session: { strategy: 'jwt' },
        },
      })
    )
    expect(engine.config.session?.maxAge).toBe(3600)
    expect(engine.config.session?.strategy).toBe('jwt')
  })

  it('keeps an explicit credentials maxAge and leaves non-credentials sessions alone', () => {
    const explicit = createAuthJsEngine(
      baseInput({
        options: {
          providers: [credentialsProvider()],
          secret: SECRET,
          session: { strategy: 'jwt', maxAge: 600 },
        },
      })
    )
    expect(explicit.config.session?.maxAge).toBe(600)
    const plain = createAuthJsEngine(baseInput({ options: { providers: [], secret: SECRET } }))
    expect(plain.config.session).toBeUndefined()
  })

  it('documents the JWT replay window and denylist deferral in the guide', () => {
    // SEC-6 pins the doc-code link: the one-hour default above is only
    // half the mitigation; builders must find the window semantics.
    const rootDir = fileURLToPath(new URL('../../../..', import.meta.url))
    const guide = readFileSync(join(rootDir, 'docs', 'guide-authjs.md'), 'utf8')
    expect(guide).toContain('### JWT post-logout replay window')
    expect(guide).toContain('no denylist is built')
    expect(guide).toContain('one hour (3600s)')
  })

  it('anchors handleRequest origins to baseURL, preserving path, query, and body', async () => {
    const spoofed = new Request('http://evil.test/api/authjs/callback/credentials?x=1', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: 'a=b' },
      body: JSON.stringify({ csrfToken: 't' }),
    })
    const anchored = anchorRequestOrigin(spoofed, 'https://app.example.com')
    expect(anchored.url).toBe('https://app.example.com/api/authjs/callback/credentials?x=1')
    expect(anchored.method).toBe('POST')
    expect(anchored.headers.get('cookie')).toBe('a=b')
    await expect(anchored.text()).resolves.toBe(JSON.stringify({ csrfToken: 't' }))
  })

  it('passes matching origins and unset baseURL through untouched', () => {
    const direct = new Request('https://app.example.com/api/authjs/csrf')
    expect(anchorRequestOrigin(direct, 'https://app.example.com')).toBe(direct)
    const unconfigured = new Request('http://localhost:3100/api/authjs/csrf')
    expect(anchorRequestOrigin(unconfigured, undefined)).toBe(unconfigured)
  })

  it('wires the adapter, claims callbacks, port, collections, and slugs', () => {
    const engine = createAuthJsEngine(baseInput())
    expect(engine.config.adapter).toBeDefined()
    expect(engine.config.callbacks?.jwt).toBeTypeOf('function')
    expect(engine.config.callbacks?.session).toBeTypeOf('function')
    expect(engine.provider.id).toBe('authjs')
    expect(engine.slugs).toEqual(defaultAuthJsSlugs)
    expect(engine.collections.map((collection) => collection.slug).sort()).toEqual(
      Object.values(defaultAuthJsSlugs).sort()
    )
  })

  it('rejects nonsense chunk slots and flows real ones to the port', () => {
    for (const chunkSlots of [-1, 1.5, Number.NaN]) {
      expect(() => createAuthJsEngine(baseInput({ chunkSlots }))).toThrow(
        'chunkSlots must be a non-negative integer'
      )
    }
    const engine = createAuthJsEngine(baseInput({ chunkSlots: 5 }))
    expect(engine.sessionCookieNames).toHaveLength(6)
    expect(engine.sessionCookieNames[5]).toBe('authjs.session-token.4')
    expect(engine.provider.sessionCookieNames).toEqual(engine.sessionCookieNames)
  })

  it('derives cookie names from the deployment origin', () => {
    const plain = createAuthJsEngine(baseInput())
    expect(plain.sessionCookieNames[0]).toBe('authjs.session-token')
    expect(plain.provider.sessionCookieNames).toEqual(plain.sessionCookieNames)

    const secure = createAuthJsEngine(baseInput({ baseURL: 'https://app.test' }))
    expect(secure.sessionCookieNames[0]).toBe('__Secure-authjs.session-token')
  })

  it('flows a custom session cookie name and its attributes to the port', () => {
    const engine = createAuthJsEngine(
      baseInput({
        chunkSlots: 1,
        options: {
          providers: [],
          secret: SECRET,
          cookies: {
            sessionToken: {
              name: 'app.sid',
              options: { domain: 'app.test', path: '/auth', secure: true, partitioned: true },
            },
          },
        },
      })
    )
    expect(engine.sessionCookieNames).toEqual(['app.sid', 'app.sid.0'])
    expect(engine.provider.sessionCookieNames).toEqual(['app.sid', 'app.sid.0'])
    // Logout must overwrite the cookie with the attributes it was set
    // with, or the browser keeps the original (different domain/path).
    const clear = engine.provider.sessionCookieClearOptions
    expect(clear?.('app.sid.0')).toEqual({
      secure: true,
      domain: 'app.test',
      path: '/auth',
      partitioned: true,
    })
    expect(clear?.('authjs.session-token')).toBeUndefined()
  })

  it('keeps the default name when only cookie attributes are customized', () => {
    const engine = createAuthJsEngine(
      baseInput({
        options: {
          providers: [],
          secret: SECRET,
          cookies: { sessionToken: { options: { domain: 'app.test' } } },
        },
      })
    )
    expect(engine.sessionCookieNames[0]).toBe('authjs.session-token')
    expect(engine.provider.sessionCookieClearOptions?.('authjs.session-token')).toMatchObject({
      domain: 'app.test',
    })
  })

  it('fails fast at wiring on a malformed baseURL', () => {
    for (const baseURL of ['nope', 'ftp://files.example.com', '/relative/path']) {
      expect(() => createAuthJsEngine(baseInput({ baseURL }))).toThrow(InvalidConfigError)
    }
    expect(() => createAuthJsEngine(baseInput({ baseURL: 'https://app.test' }))).not.toThrow()
  })
})

describe('engine session api', () => {
  it('returns null without a cookie and never touches Auth.js', async () => {
    const { payload, find } = fakePayload()
    const engine = createAuthJsEngine(baseInput({ getPayload: () => Promise.resolve(payload) }))
    const result = await engine.provider.getSession(new Headers({ host: 'app.test' }))
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value).toBeNull()
    }
    expect(find).not.toHaveBeenCalled()
  })

  it('requires a host header to build the session request', async () => {
    const engine = createAuthJsEngine(baseInput())
    const result = await engine.provider.getSession(
      new Headers({ cookie: 'authjs.session-token=t' })
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error.message).toContain('getSession')
    }
  })

  it('treats an unknown token as anonymous, never a phantom user', async () => {
    // Auth.js finds no session for the garbage token, so the read resolves
    // to null — the same anonymous outcome as a missing cookie.
    const engine = createAuthJsEngine(baseInput())
    const result = await engine.provider.getSession(
      new Headers({ cookie: 'authjs.session-token=garbage', host: 'app.test' })
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value).toBeNull()
    }
  })
})

describe('engine session api: non-OK Auth.js answers', () => {
  it('reads a session Auth.js refuses to serve as anonymous, not as an error', async () => {
    // `trustHost: false` makes raw core answer every request with a 500
    // configuration error (`UntrustedHost`); the read must not parse
    // that error body as a session.
    const error = vi.fn()
    const engine = createAuthJsEngine(
      baseInput({
        options: { providers: [], secret: SECRET, trustHost: false, logger: { error } },
      })
    )
    const result = await engine.provider.getSession(
      new Headers({ cookie: 'authjs.session-token=t', host: 'app.test' })
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value).toBeNull()
    }
    expect(error).toHaveBeenCalled()
  })
})

describe('engine revocation', () => {
  it('is a no-op for jwt sessions and never touches storage', async () => {
    const { payload, find, remove } = fakePayload()
    const engine = createAuthJsEngine(
      baseInput({
        getPayload: () => Promise.resolve(payload),
        options: { providers: [], secret: SECRET, session: { strategy: 'jwt' } },
      })
    )
    const result = await engine.provider.revokeSession('tok-1')
    expect(result.isOk()).toBe(true)
    expect(find).not.toHaveBeenCalled()
    expect(remove).not.toHaveBeenCalled()
  })

  it('deletes database sessions through the adapter', async () => {
    const find = vi.fn(() =>
      Promise.resolve({
        docs: [
          {
            id: 'doc-9',
            sessionToken: 'tok-1',
            userId: 'au-1',
            expires: '2026-06-01T00:00:00.000Z',
          },
        ],
        totalDocs: 1,
      })
    )
    const remove = vi.fn(() => Promise.resolve({ docs: [], errors: [] }))
    const payload = { find, delete: remove } as unknown as Payload
    const engine = createAuthJsEngine(baseInput({ getPayload: () => Promise.resolve(payload) }))
    const result = await engine.provider.revokeSession('tok-1')
    expect(result.isOk()).toBe(true)
    expect(remove).toHaveBeenCalledWith({
      collection: 'aj-sessions',
      id: 'doc-9',
      overrideAccess: true,
    })
  })

  it('refuses to report an unknown handle as revoked', async () => {
    const find = vi.fn(() => Promise.resolve({ docs: [], totalDocs: 0 }))
    const remove = vi.fn()
    const payload = { find, delete: remove } as unknown as Payload
    const engine = createAuthJsEngine(baseInput({ getPayload: () => Promise.resolve(payload) }))
    const result = await engine.provider.revokeSession('no-such-token')
    expect(result.isErr()).toBe(true)
    expect(remove).not.toHaveBeenCalled()
  })

  it('revokes every database session for a user, verified by a recount', async () => {
    // A bulk delete result that is not an object carries no per-row
    // errors to inspect; the recount alone decides.
    const remove = vi.fn(() => Promise.resolve(null))
    const count = vi.fn(() => Promise.resolve({ totalDocs: 0 }))
    const payload = { delete: remove, count } as unknown as Payload
    const engine = createAuthJsEngine(baseInput({ getPayload: () => Promise.resolve(payload) }))
    const result = await engine.provider.revokeUserSessions?.('au-1')
    expect(result?.isOk()).toBe(true)
    expect(remove).toHaveBeenCalledWith({
      collection: 'aj-sessions',
      where: { userId: { equals: 'au-1' } },
      overrideAccess: true,
    })
    expect(count).toHaveBeenCalledTimes(1)
  })

  it('fails revoke-all when rows survive the bulk delete', async () => {
    const remove = vi.fn(() => Promise.resolve(null))
    const count = vi.fn(() => Promise.resolve({ totalDocs: 2 }))
    const payload = { delete: remove, count } as unknown as Payload
    const engine = createAuthJsEngine(baseInput({ getPayload: () => Promise.resolve(payload) }))
    const result = await engine.provider.revokeUserSessions?.('au-1')
    expect(result?.isErr()).toBe(true)
    if (result?.isErr()) {
      expect(result.error.message).toContain('revokeUserSessions')
    }
  })

  it('omits revoke-all for jwt deployments', () => {
    const engine = createAuthJsEngine(
      baseInput({ options: { providers: [], secret: SECRET, session: { strategy: 'jwt' } } })
    )
    expect(engine.provider.revokeUserSessions).toBeUndefined()
  })
})
