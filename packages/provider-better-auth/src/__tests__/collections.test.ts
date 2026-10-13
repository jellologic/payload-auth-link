import { InvalidConfigError } from '@payload-auth-link/core'
import type { Field } from 'payload'
import { describe, expect, it } from 'vitest'
import {
  createBetterAuthCollections,
  customModelSlug,
  defaultBetterAuthSlugs,
  defaultCustomSlug,
} from '../collections.js'

describe('createBetterAuthCollections', () => {
  it('creates one hidden deny-all collection per core model', () => {
    const collections = createBetterAuthCollections()
    expect(collections.map((collection) => collection.slug).sort()).toEqual(
      Object.values(defaultBetterAuthSlugs).sort()
    )
    for (const collection of collections) {
      expect(collection.admin?.hidden).toBe(true)
      expect(typeof collection.access?.create).toBe('function')
      expect(typeof collection.access?.read).toBe('function')
      expect(typeof collection.access?.update).toBe('function')
      expect(typeof collection.access?.delete).toBe('function')
      const names = (collection.fields ?? []).flatMap((field) =>
        'name' in field ? [field.name] : []
      )
      expect(names).toContain('baId')
    }
  })

  it('covers the canonical Better Auth fields', () => {
    const collections = createBetterAuthCollections()
    const bySlug = new Map(collections.map((collection) => [collection.slug, collection]))
    const namesOf = (slug: string): string[] =>
      (bySlug.get(slug)?.fields ?? []).flatMap((field) => ('name' in field ? [field.name] : []))
    expect(namesOf('ba-users')).toEqual(
      expect.arrayContaining(['baId', 'email', 'name', 'emailVerified', 'image'])
    )
    expect(namesOf('ba-sessions')).toEqual(
      expect.arrayContaining(['baId', 'userId', 'token', 'expiresAt', 'ipAddress', 'userAgent'])
    )
    expect(namesOf('ba-accounts')).toEqual(
      expect.arrayContaining([
        'baId',
        'userId',
        'accountId',
        'providerId',
        'password',
        'accessToken',
        'refreshToken',
        'idToken',
        'accessTokenExpiresAt',
        'refreshTokenExpiresAt',
        'scope',
      ])
    )
    expect(namesOf('ba-verifications')).toEqual(
      expect.arrayContaining(['baId', 'identifier', 'value', 'expiresAt'])
    )
    expect(namesOf('ba-rate-limits')).toEqual(
      expect.arrayContaining(['baId', 'key', 'count', 'lastRequest'])
    )
  })

  it('honors slug overrides', () => {
    const collections = createBetterAuthCollections({ slugs: { user: 'custom-users' } })
    expect(collections.map((collection) => collection.slug)).toContain('custom-users')
  })

  it('appends custom fields with mapped column types', () => {
    const collections = createBetterAuthCollections({
      customFields: {
        user: [
          { name: 'favoriteColor', type: 'text' },
          { name: 'loginCount', type: 'number', required: true },
          { name: 'nickname', type: 'text', unique: true },
          { name: 'optedIn', type: 'boolean' },
          { name: 'trialEndsAt', type: 'date' },
          { name: 'preferences', type: 'json' },
        ],
      },
    })
    const fields = (collections.find((c) => c.slug === 'ba-users')?.fields ?? []).filter(
      (field): field is Field & { name: string } => 'name' in field
    )
    const byName = new Map(fields.map((field) => [field.name, field]))
    expect(byName.get('favoriteColor')).toMatchObject({ type: 'text', required: false })
    expect(byName.get('loginCount')).toMatchObject({ type: 'number', required: true })
    expect(byName.get('nickname')).toMatchObject({ type: 'text', unique: true, index: true })
    expect(byName.get('optedIn')).toMatchObject({ type: 'checkbox' })
    expect(byName.get('trialEndsAt')).toMatchObject({ type: 'date' })
    expect(byName.get('preferences')).toMatchObject({ type: 'json' })
    // Core columns untouched.
    expect(byName.get('email')).toMatchObject({ type: 'email' })
  })

  it('keeps ba-users.name NOT NULL while accepting BA empty-string writes (B2)', () => {
    const collections = createBetterAuthCollections()
    const users = collections.find((collection) => collection.slug === 'ba-users')
    const name = (users?.fields ?? []).find((field) => 'name' in field && field.name === 'name')
    // The physical column must stay NOT NULL (0.1.1 shape): dropping
    // `required` forced a SQLite table rebuild that wedged upgrades.
    expect(name).toMatchObject({ type: 'text', required: true })
    // The custom validator is what lets BA's `name: ""` writes through.
    const validate = name !== undefined && 'validate' in name ? name.validate : undefined
    expect(typeof validate).toBe('function')
    if (typeof validate === 'function') {
      // Field validate receives (value, options); ours reads value only.
      const check = validate as (value: unknown) => unknown
      expect(check('')).toBe(true)
      expect(check('Ada')).toBe(true)
      expect(check(undefined)).toBe(true)
      expect(check(null)).not.toBe(true)
      expect(check(42)).not.toBe(true)
    }
  })

  it('builds custom model collections with baId and default slugs', () => {
    expect(defaultCustomSlug('organization')).toBe('ba-organization')
    const collections = createBetterAuthCollections({
      customModels: [
        {
          model: 'organization',
          fields: [
            { name: 'name', type: 'text', required: true },
            { name: 'slug', type: 'text', required: true, unique: true },
          ],
        },
        { model: 'member', slug: 'org-members', label: 'Org member', fields: [] },
      ],
    })
    const slugs = collections.map((collection) => collection.slug)
    expect(slugs).toContain('ba-organization')
    expect(slugs).toContain('org-members')
    const org = collections.find((collection) => collection.slug === 'ba-organization')
    expect(org?.labels).toMatchObject({ singular: 'Better Auth organization' })
    expect(org?.admin?.hidden).toBe(true)
    const names = (org?.fields ?? []).flatMap((field) => ('name' in field ? [field.name] : []))
    expect(names).toEqual(expect.arrayContaining(['baId', 'name', 'slug']))
    const member = collections.find((collection) => collection.slug === 'org-members')
    expect(member?.labels).toMatchObject({ singular: 'Org member' })
  })

  it('rejects custom declarations that collide or lie empty', () => {
    expect(() =>
      createBetterAuthCollections({ customFields: { user: [{ name: 'email', type: 'text' }] } })
    ).toThrow(InvalidConfigError)
    expect(() =>
      createBetterAuthCollections({ customFields: { user: [{ name: 'baId', type: 'text' }] } })
    ).toThrow('collides with a built-in field')
    expect(() =>
      createBetterAuthCollections({
        customFields: {
          user: [
            { name: 'dup', type: 'text' },
            { name: 'dup', type: 'text' },
          ],
        },
      })
    ).toThrow('duplicate custom field "dup"')
    expect(() =>
      createBetterAuthCollections({ customModels: [{ model: 'user', fields: [] }] })
    ).toThrow('collides with a core model')
    expect(() =>
      createBetterAuthCollections({
        customModels: [
          { model: 'organization', fields: [] },
          { model: 'organization', fields: [] },
        ],
      })
    ).toThrow('duplicate custom model "organization"')
    expect(() =>
      createBetterAuthCollections({ customModels: [{ model: '', fields: [] }] })
    ).toThrow('must not be empty')
  })

  it('rejects empty, duplicate, and colliding slugs at wiring time', () => {
    expect(() => createBetterAuthCollections({ slugs: { user: '' } })).toThrow(
      'slug for model "user" must be a non-empty string'
    )
    expect(() =>
      createBetterAuthCollections({ slugs: { user: 'ba-sessions', session: 'ba-sessions' } })
    ).toThrow('models "user" and "session" share slug "ba-sessions"')
    expect(() =>
      createBetterAuthCollections({
        customModels: [{ model: 'organization', slug: 'ba-users', fields: [] }],
      })
    ).toThrow('share slug "ba-users"')
    expect(() => customModelSlug({ model: 'organization', slug: '', fields: [] })).toThrow(
      'custom model "organization" slug must not be empty'
    )
    expect(customModelSlug({ model: 'organization', fields: [] })).toBe('ba-organization')
  })
})
