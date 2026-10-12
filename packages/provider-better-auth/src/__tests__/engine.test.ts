import { wellKnownProviderIds } from '@payload-auth-link/core'
import { magicLink } from 'better-auth/plugins/magic-link'
import { organization } from 'better-auth/plugins/organization'
import type { Payload } from 'payload'
import { describe, expect, it } from 'vitest'
import { defaultBetterAuthSlugs } from '../collections.js'
import { createBetterAuthEngine } from '../engine.js'
import { UnsupportedSchemaError } from '../errors.js'

const getPayload = (): Promise<Payload> => Promise.reject(new Error('no Payload in unit test'))

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

  it('fails loud when a plugin extends a core model (v1 supports core fields only)', async () => {
    const engine = createBetterAuthEngine({
      getPayload,
      options: { plugins: [organization()] },
    })
    // Better Auth defers adapter init, so the failure surfaces on $context.
    await expect(engine.auth.$context).rejects.toBeInstanceOf(UnsupportedSchemaError)
  })
})
