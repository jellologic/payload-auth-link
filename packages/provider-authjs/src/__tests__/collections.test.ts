import { describe, expect, it } from 'vitest'
import { createAuthJsCollections, defaultAuthJsSlugs } from '../collections.js'

describe('createAuthJsCollections', () => {
  it('creates one hidden deny-all collection per model', () => {
    const collections = createAuthJsCollections()
    expect(collections.map((collection) => collection.slug).sort()).toEqual(
      Object.values(defaultAuthJsSlugs).sort()
    )
    expect(Object.values(defaultAuthJsSlugs).sort()).toEqual([
      'aj-accounts',
      'aj-authenticators',
      'aj-sessions',
      'aj-users',
      'aj-verification-tokens',
    ])
    for (const collection of collections) {
      expect(collection.admin?.hidden).toBe(true)
      expect(typeof collection.access?.create).toBe('function')
      expect(typeof collection.access?.read).toBe('function')
      expect(typeof collection.access?.update).toBe('function')
      expect(typeof collection.access?.delete).toBe('function')
    }
  })

  it('covers the canonical Auth.js fields plus the credentials extension', () => {
    const collections = createAuthJsCollections()
    const bySlug = new Map(collections.map((collection) => [collection.slug, collection]))
    const namesOf = (slug: string): string[] =>
      (bySlug.get(slug)?.fields ?? []).flatMap((field) => ('name' in field ? [field.name] : []))
    expect(namesOf(defaultAuthJsSlugs.user)).toEqual(
      expect.arrayContaining(['auId', 'email', 'name', 'image', 'passwordHash', 'emailVerified'])
    )
    expect(namesOf(defaultAuthJsSlugs.account)).toEqual(
      expect.arrayContaining([
        'key',
        'provider',
        'providerAccountId',
        'userId',
        'type',
        'access_token',
        'refresh_token',
        'expires_at',
      ])
    )
    expect(namesOf(defaultAuthJsSlugs.session)).toEqual(
      expect.arrayContaining(['sessionToken', 'userId', 'expires'])
    )
    expect(namesOf(defaultAuthJsSlugs.verificationToken)).toEqual(
      expect.arrayContaining(['key', 'identifier', 'token', 'expires'])
    )
    expect(namesOf(defaultAuthJsSlugs.authenticator)).toEqual(
      expect.arrayContaining([
        'credentialID',
        'userId',
        'credentialPublicKey',
        'counter',
        'credentialBackedUp',
        'credentialDeviceType',
      ])
    )
  })

  it('makes verification-token uniqueness composite, not token-only', () => {
    // Duplicate 6-digit OTP codes hash identically across identifiers, so
    // `token` alone must not be unique; the composite `key` carries
    // (identifier, token) uniqueness instead (spikes S2/S7).
    const collections = createAuthJsCollections()
    const tokens = collections.find(
      (collection) => collection.slug === defaultAuthJsSlugs.verificationToken
    )
    const fieldNamed = (name: string) =>
      (tokens?.fields ?? []).find((field) => 'name' in field && field.name === name)
    expect(fieldNamed('key')).toMatchObject({ unique: true })
    // Upgrade safety (B2/B6): `key` arrived in 0.2.0 and must never be
    // DB-required — a NOT NULL addition breaks pre-0.2.0 databases on
    // every adapter. This assertion is the tripwire.
    expect(fieldNamed('key')).not.toMatchObject({ required: true })
    expect(fieldNamed('token')).not.toMatchObject({ unique: true })
  })

  it('honors slug overrides and custom access', () => {
    const collections = createAuthJsCollections({
      slugs: { user: 'custom-users' },
      access: {
        create: () => false,
        read: () => true,
        update: () => false,
        delete: () => false,
      },
    })
    const bySlug = new Map(collections.map((collection) => [collection.slug, collection]))
    expect(bySlug.has('custom-users')).toBe(true)
    expect(bySlug.has(defaultAuthJsSlugs.session)).toBe(true)
    for (const collection of collections) {
      expect(collection.access?.read).toBeDefined()
    }
  })

  it('rejects empty, duplicate, and unknown slug overrides at wiring time', () => {
    expect(() => createAuthJsCollections({ slugs: { user: '' } })).toThrow(
      'slug for model "user" must be a non-empty string'
    )
    expect(() =>
      createAuthJsCollections({ slugs: { user: 'aj-sessions', session: 'aj-sessions' } })
    ).toThrow('models "user" and "session" share slug "aj-sessions"')
    expect(() =>
      createAuthJsCollections({ slugs: { usr: 'x' } as unknown as { user: string } })
    ).toThrow('unknown model "usr" in slug overrides')
  })
})
