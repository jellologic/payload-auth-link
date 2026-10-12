import { InvalidConfigError } from '@payload-auth-link/core'
import type { AuthConfig } from '@auth/core'
import Credentials from '@auth/core/providers/credentials'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Payload } from 'payload'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defaultAuthJsSlugs } from '../collections.js'
import { anchorRequestOrigin, createAuthJsEngine, type AuthJsEngineInput } from '../engine.js'

const SECRET = 'authjs-engine-test-secret!!'

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
})
