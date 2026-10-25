import { engineCreateMarker, InvalidConfigError } from '@payload-auth-link/core'
import type { CollectionConfig } from 'payload'
import { describe, expect, it } from 'vitest'
import { applyUsersCollection, fieldName, withAdoptedCollectionHardening } from '../collections.js'
import { wireOptions } from '../options.js'
import { createAuthLinkStrategy, strategyName } from '../strategy.js'
import { createStubProvider } from './stub-provider.js'

function wired() {
  const { provider } = createStubProvider()
  const options = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [provider],
  })
  return { options, strategy: createAuthLinkStrategy(options) }
}

describe('applyUsersCollection', () => {
  it('creates the users collection when missing', () => {
    const { options, strategy } = wired()
    const result = applyUsersCollection([], options, strategy)
    expect(result).toHaveLength(1)
    const users = result[0]
    expect(users?.slug).toBe('users')
    expect(users?.fields.map((field) => fieldName(field))).toEqual([
      'email',
      'roles',
      'identities',
      'phone',
      'suspendedUntil',
      'suspendReason',
      'linkable',
      'linkableEmail',
    ])
    expect(users?.auth).toMatchObject({ strategies: [{ name: strategyName }] })
    expect(users?.hooks?.beforeValidate).toHaveLength(1)
  })

  it('extends an existing collection without overwriting', () => {
    const { options, strategy } = wired()
    const hook = () => undefined
    const existing: CollectionConfig = {
      slug: 'users',
      auth: true,
      fields: [{ name: 'nickname', type: 'text' }],
      hooks: { beforeValidate: [hook] },
    }
    const result = applyUsersCollection([existing], options, strategy)
    const users = result[0]
    expect(users?.fields.map((field) => fieldName(field))).toEqual([
      'nickname',
      'roles',
      'email',
      'identities',
      'phone',
      'suspendedUntil',
      'suspendReason',
      'linkable',
      'linkableEmail',
    ])
    expect(users?.hooks?.beforeValidate).toHaveLength(2)
    expect(users?.hooks?.beforeValidate?.[0]).toBe(hook)
    const auth = users?.auth
    expect(typeof auth === 'object' && auth !== null && 'strategies' in auth).toBe(true)
  })

  it('appends to existing strategies without duplicating', () => {
    const { options, strategy } = wired()
    const other = { name: 'other', authenticate: () => Promise.resolve({ user: null }) }
    const existing: CollectionConfig = {
      slug: 'users',
      auth: { strategies: [other, strategy] },
      fields: [],
    }
    const result = applyUsersCollection([existing], options, strategy)
    const auth = result[0]?.auth
    if (typeof auth !== 'object' || auth === null || !('strategies' in auth)) {
      throw new Error('expected strategies array')
    }
    expect(auth.strategies?.map((candidate) => candidate.name)).toEqual(['other', strategyName])
  })

  it('throws on field-name collisions', () => {
    const { options, strategy } = wired()
    const existing: CollectionConfig = {
      slug: 'users',
      fields: [{ name: 'roles', type: 'text' }],
    }
    expect(() => applyUsersCollection([existing], options, strategy)).toThrow(InvalidConfigError)
  })

  describe('adopting an existing roles field (migration from payload-auth-style schemas)', () => {
    const compatible: CollectionConfig = {
      slug: 'users',
      fields: [
        {
          name: 'roles',
          type: 'select',
          hasMany: true,
          options: [
            { label: 'admin', value: 'admin' },
            { label: 'user', value: 'user' },
            { label: 'staff', value: 'staff' },
          ],
        },
      ],
    }

    it('adopts a compatible multi-select covering every configured role', () => {
      const { options, strategy } = wired()
      const result = applyUsersCollection([compatible], options, strategy)
      const users = result[0] as CollectionConfig
      const roles = users.fields.find((field) => fieldName(field) === 'roles') as Record<
        string,
        unknown
      >
      // Governance imposed; host options preserved.
      expect(roles.required).toBe(true)
      expect(roles.defaultValue).toEqual(['user'])
      const access = roles.access as { create?: unknown; update?: unknown; read?: unknown }
      expect(typeof access.create).toBe('function')
      expect(typeof access.update).toBe('function')
      expect(typeof access.read).toBe('function')
      expect(roles.options).toEqual(
        compatible.fields[0] && (compatible.fields[0] as Record<string, unknown>).options
      )
      // The identity rows and governance fields are still injected.
      expect(users.fields.some((field) => fieldName(field) === 'identities')).toBe(true)
    })

    it('rejects single-select and missing-role shapes with remediation', () => {
      const { options, strategy } = wired()
      const single: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'roles', type: 'select', hasMany: false, options: ['admin', 'user'] }],
      }
      expect(() => applyUsersCollection([single], options, strategy)).toThrow(/hasMany is not true/)
      const missing: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'roles', type: 'select', hasMany: true, options: ['user'] }],
      }
      expect(() => applyUsersCollection([missing], options, strategy)).toThrow(/'admin'/)
      const text: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'roles', type: 'text' }],
      }
      expect(() => applyUsersCollection([text], options, strategy)).toThrow(/not a select/)
    })

    it('adopts a renamed roles field via rolesField remapping', () => {
      const { provider } = createStubProvider()
      const options = wireOptions({
        baseUrl: 'http://auth-link.test',
        roles: ['admin', 'user'],
        defaultRole: 'user',
        rolesField: 'role',
        providers: [provider],
      })
      const strategy = createAuthLinkStrategy(options)
      const existing: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'role', type: 'select', hasMany: true, options: ['admin', 'user'] }],
      }
      const result = applyUsersCollection([existing], options, strategy)
      const users = result[0] as CollectionConfig
      const role = users.fields.find((field) => fieldName(field) === 'role') as Record<
        string,
        unknown
      >
      expect(role.required).toBe(true)
      expect(typeof (role.access as { create?: unknown }).create).toBe('function')
    })
  })

  describe('JIT-linking proof marker (GHSA-98hq-hh6v-2p2r)', () => {
    function usersOf(result: ReturnType<typeof applyUsersCollection>) {
      return result[0] as CollectionConfig
    }
    function markerHookOf(users: CollectionConfig) {
      // The proof marker is the LAST beforeChange hook (the roles
      // normalizer runs first, issue #124).
      const hook = users.hooks?.beforeChange?.at(-1)
      expect(hook).toBeTypeOf('function')
      return hook as (args: {
        operation: string
        data: Record<string, unknown>
        req: { user?: unknown; context?: Record<string, unknown> }
      }) => void
    }

    it('injects the linkable field (manager-write, manager-read)', () => {
      const { options, strategy } = wired()
      const users = usersOf(applyUsersCollection([], options, strategy))
      const field = users.fields.find((f) => fieldName(f) === 'linkable') as Record<string, unknown>
      expect(field?.defaultValue).toBe(false)
      const access = field.access as { update?: unknown; read?: unknown }
      expect(typeof access.update).toBe('function')
      expect(typeof access.read).toBe('function')
    })

    it('marks manager-created and engine-marked creates proven; plain creates unproven', () => {
      const { options, strategy } = wired()
      const hook = markerHookOf(usersOf(applyUsersCollection([], options, strategy)))
      const manager = { user: { id: '1', email: 'a@b.co', roles: ['admin'] } }
      const plain = { user: { id: '2', email: 'p@b.co', roles: ['user'] } }
      const data: Record<string, unknown> = { email: 'x@y.z' }

      hook({ operation: 'create', data, req: { ...manager, context: {} } })
      expect(data.linkable).toBe(true)

      const data2: Record<string, unknown> = { email: 'x@y.z' }
      hook({
        operation: 'create',
        data: data2,
        req: { user: undefined, context: { 'payload-auth-link:create': true } },
      })
      expect(data2.linkable).toBe(true)

      const data3: Record<string, unknown> = { email: 'x@y.z' }
      hook({ operation: 'create', data: data3, req: plain })
      expect(data3.linkable).toBe(false)

      const data4: Record<string, unknown> = { email: 'x@y.z', linkable: true }
      hook({ operation: 'create', data: data4, req: plain })
      expect(data4.linkable).toBe(true)
    })

    it('fills collection-level create/read defaults; host-declared wins', async () => {
      const { options, strategy } = wired()
      const existing: CollectionConfig = {
        slug: 'users',
        fields: [],
        access: { create: () => true, read: () => true },
      }
      const users = usersOf(applyUsersCollection([existing], options, strategy))
      const access = users.access as Record<string, unknown>
      // Host-declared functions win over the defaults. The account
      // controls (GHSA-f4hj) wrap every declared access function —
      // identity is intentionally not preserved, so this asserts the
      // wrapped fn still resolves to the host's decision.
      expect(access.create).not.toBe(undefined)
      expect(access.create).not.toBeTypeOf('boolean')
      expect(access.read).not.toBe(undefined)
      expect(access.read).not.toBeTypeOf('boolean')
      // Undeclared keys are gap-filled with the fail-closed defaults.
      const empty: CollectionConfig = { slug: 'users', fields: [] }
      const filled = usersOf(applyUsersCollection([empty], options, strategy))
      const gapAccess = filled.access as {
        create?: (args: { req: { user?: unknown } }) => boolean
        read?: unknown
      }
      // The account-controls belt wraps every access fn (GHSA-f4hj);
      // the wrapped decisions are async.
      const granted = (await Promise.resolve(
        gapAccess.create?.({ req: { user: { roles: ['admin'] } } })
      )) as unknown
      const denied = (await Promise.resolve(
        gapAccess.create?.({ req: { user: { roles: ['user'] } } })
      )) as unknown
      expect(granted).toBe(true)
      expect(denied).toBe(false)
      expect(gapAccess.read).toBeTypeOf('function')
    })
  })

  describe('email/password fail-closed guards (GHSA-8524)', () => {
    const usersOf = (result: ReturnType<typeof applyUsersCollection>) =>
      result[0] as CollectionConfig
    it('injects the email field with fail-closed update access', () => {
      const { options, strategy } = wired()
      const users = usersOf(applyUsersCollection([], options, strategy))
      const email = users.fields.find((f) => fieldName(f) === 'email') as {
        access?: { update?: (args: { req: { user?: unknown }; doc?: unknown }) => boolean }
      }
      const req = (roles: string[]) => ({ user: { id: 'self', roles } })
      const doc = { id: 'self', identities: [{ providerId: 'stub', providerUserId: '1' }] }
      expect(email.access?.update?.({ req: req(['admin']), doc })).toBe(true)
      expect(email.access?.update?.({ req: req(['user']), doc })).toBe(false)
      expect(
        email.access?.update?.({ req: req(['user']), doc: { id: 'self', identities: [] } })
      ).toBe(true)
      // Never another user's address, linked or not.
      expect(
        email.access?.update?.({ req: req(['user']), doc: { id: 'other', identities: [] } })
      ).toBe(false)
    })

    it('strips password writes from non-managers in beforeOperation; managers keep them', () => {
      const { options, strategy } = wired()
      const users = usersOf(applyUsersCollection([], options, strategy))
      const hook = users.hooks?.beforeOperation?.[0] as (args: {
        args: { data: Record<string, unknown> }
        operation: string
        req: { user?: unknown }
      }) => unknown
      const plain = {
        args: { data: { password: 'X-1', name: 'n' } },
        operation: 'update',
        req: { user: { roles: ['user'] } },
      }
      const stripped = hook(plain) as { data: Record<string, unknown> }
      expect(stripped.data.password).toBeUndefined()
      expect(stripped.data.name).toBe('n')
      const manager = {
        args: { data: { password: 'X-1' } },
        operation: 'update',
        req: { user: { roles: ['admin'] } },
      }
      const kept = hook(manager) as { data: Record<string, unknown> }
      expect(kept.data.password).toBe('X-1')
    })

    it('gap-fills a host email field that lacks update access; host-declared wins', () => {
      const { options, strategy } = wired()
      const unguarded: CollectionConfig = {
        slug: 'users',
        fields: [{ name: 'email', type: 'email', required: true }],
      }
      const users = usersOf(applyUsersCollection([unguarded], options, strategy))
      const email = users.fields.find((f) => fieldName(f) === 'email') as {
        access?: { update?: unknown }
      }
      expect(typeof email.access?.update).toBe('function')

      const declared: CollectionConfig = {
        slug: 'users',
        fields: [
          {
            name: 'email',
            type: 'email',
            required: true,
            access: { update: () => true },
          },
        ],
      }
      const kept = usersOf(applyUsersCollection([declared], options, strategy))
      const keptEmail = kept.fields.find((f) => fieldName(f) === 'email') as {
        access?: { update?: unknown }
      }
      expect(keptEmail.access?.update).toBe(
        declared.fields[0] && (declared.fields[0] as { access: { update: unknown } }).access.update
      )
    })
  })

  it('names the collided field, with the identities-specific remediation', () => {
    const { options, strategy } = wired()
    const collide = (name: string) => () =>
      applyUsersCollection([{ slug: 'users', fields: [{ name, type: 'text' }] }], options, strategy)
    expect(collide('identities')).toThrow(
      "users collection 'users' already has a 'identities' field; rename it or point the collection map elsewhere (the identities array is engine-managed and cannot be adopted)"
    )
    expect(collide('suspendedUntil')).toThrow(
      "users collection 'users' already has a 'suspendedUntil' field; rename it or point the collection map elsewhere"
    )
  })

  it("keeps an adopted roles select's own defaultValue", () => {
    const { options, strategy } = wired()
    const result = applyUsersCollection(
      [
        {
          slug: 'users',
          fields: [
            {
              name: 'roles',
              type: 'select',
              hasMany: true,
              options: ['admin', 'user'],
              defaultValue: ['admin'],
            },
          ],
        },
      ],
      options,
      strategy
    )
    const roles = result[0]?.fields.find((field) => fieldName(field) === 'roles')
    expect(roles && 'defaultValue' in roles ? roles.defaultValue : undefined).toEqual(['admin'])
  })

  it('validates the phone field as E.164 (CAP-9), allowing it to be cleared', () => {
    const { options, strategy } = wired()
    const users = applyUsersCollection([], options, strategy)[0]
    const phone = users?.fields.find((field) => fieldName(field) === 'phone')
    const validate =
      phone !== undefined && 'validate' in phone && typeof phone.validate === 'function'
        ? (phone.validate as (value: unknown) => true | string)
        : undefined
    expect(validate).toBeDefined()
    expect(validate?.('+14155550132')).toBe(true)
    expect(validate?.('')).toBe(true)
    expect(validate?.(null)).toBe(true)
    expect(typeof validate?.('555-0132')).toBe('string')
  })

  describe('host-declared access on the users collection', () => {
    // A user from another auth collection: the account-control belt
    // passes it straight to the wrapped decision.
    const req = { user: { id: 'o1', collection: 'admins', email: 'o1@test.dev' }, context: {} }
    type AccessFn = (args: { req: typeof req }) => unknown

    function accessOf(access: CollectionConfig['access']): Record<string, AccessFn | undefined> {
      const { options, strategy } = wired()
      const users = applyUsersCollection(
        [{ slug: 'users', fields: [], ...(access === undefined ? {} : { access }) }],
        options,
        strategy
      )[0]
      return (users?.access ?? {}) as Record<string, AccessFn | undefined>
    }

    it('keeps host delete / readVersions decisions behind the belt', async () => {
      const access = accessOf({ delete: () => true, readVersions: () => true })
      await expect(access.delete?.({ req })).resolves.toBe(true)
      await expect(access.readVersions?.({ req })).resolves.toBe(true)
    })

    it('fills defaults that refuse a user without a roles array (fail closed)', async () => {
      const access = accessOf(undefined)
      await expect(access.delete?.({ req })).resolves.toBe(false)
      await expect(access.readVersions?.({ req })).resolves.toBe(false)
      // Not a manager: read is constrained to the user's own document.
      await expect(access.read?.({ req })).resolves.toEqual({ email: { equals: 'o1@test.dev' } })
    })
  })

  it('never mutates its input', () => {
    const { options, strategy } = wired()
    const existing: CollectionConfig = { slug: 'users', fields: [] }
    const before = JSON.stringify(existing)
    applyUsersCollection([existing], options, strategy)
    expect(JSON.stringify(existing)).toBe(before)
  })
})

describe('adoptIdentityHook — the identity row at creation (issue #132)', () => {
  function identityHookOf(
    options: Parameters<typeof applyUsersCollection>[1],
    strategy: Parameters<typeof applyUsersCollection>[2]
  ) {
    const users = applyUsersCollection([], options, strategy)[0]
    const hook = users?.hooks?.afterChange?.[0]
    expect(hook).toBeTypeOf('function')
    return hook as (args: {
      doc: Record<string, unknown>
      operation: string
      req: {
        context?: Record<string, unknown>
        payload: { update: (args: unknown) => Promise<unknown> }
      }
    }) => Promise<void>
  }

  it('writes the identity row for an engine-marked create over a provider-owned-id port', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    await hook({
      doc: { id: 7, email: 'guest@test.dev', identities: [] },
      operation: 'create',
      req: {
        context: { [engineCreateMarker]: true },
        payload: {
          update: (args: unknown) => {
            updates.push(args)
            return Promise.resolve()
          },
        },
      },
    })
    expect(updates).toHaveLength(1)
    const written = updates[0] as { data: { identities: unknown } }
    const rows = written.data.identities as
      | {
          providerId: unknown
          providerUserId: unknown
          email: unknown
          linkedAt: unknown
        }[]
      | undefined
    expect(rows).toHaveLength(1)
    expect(rows?.[0]?.providerId).toBe(provider.id)
    expect(rows?.[0]?.providerUserId).toBe('7')
    expect(rows?.[0]?.email).toBe('guest@test.dev')
    expect(typeof rows?.[0]?.linkedAt).toBe('string')
  })

  it('leaves an operator-created document alone (no engine marker)', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    await hook({
      doc: { id: 8, email: 'operator@test.dev', identities: [] },
      operation: 'create',
      req: {
        context: {},
        payload: {
          update: (args: unknown) => {
            updates.push(args)
            return Promise.resolve()
          },
        },
      },
    })
    expect(updates).toHaveLength(0)
  })

  it('a failed identity write is non-fatal and logged (#135)', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    await hook({
      doc: { id: 12, email: 'gone@test.dev', identities: [] },
      operation: 'create',
      req: {
        context: { [engineCreateMarker]: true },
        payload: {
          update: () => Promise.reject(new Error('Not Found')),
        },
      },
    })
    // No throw reached the caller: the JIT link attaches the identity
    // on first resolution instead.
  })

  it('leaves a document that already carries identities alone', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    await hook({
      doc: {
        id: 10,
        email: 'linked@test.dev',
        identities: [{ providerId: provider.id, providerUserId: 'elsewhere' }],
      },
      operation: 'create',
      req: {
        context: { [engineCreateMarker]: true },
        payload: {
          update: (args: unknown) => {
            updates.push(args)
            return Promise.resolve()
          },
        },
      },
    })
    expect(updates).toHaveLength(0)
  })

  it('a non-record document is skipped', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    await hook({
      doc: null as unknown as Record<string, unknown>,
      operation: 'create',
      req: {
        context: { [engineCreateMarker]: true },
        payload: {
          update: (args: unknown) => {
            updates.push(args)
            return Promise.resolve()
          },
        },
      },
    })
    expect(updates).toHaveLength(0)
  })

  it('a document without a usable id is skipped; a missing email stores empty', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    const req = {
      context: { [engineCreateMarker]: true },
      payload: {
        update: (args: unknown) => {
          updates.push(args)
          return Promise.resolve()
        },
      },
    }
    await hook({ doc: { identities: [] }, operation: 'create', req })
    expect(updates).toHaveLength(0)
    await hook({ doc: { id: 13, identities: [] }, operation: 'create', req })
    expect(updates).toHaveLength(1)
    const written = updates[0] as { data: { identities: { email: unknown }[] } }
    expect(written.data.identities[0]?.email).toBe('')
  })

  it('a request with no context object is not an engine create', async () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [owned],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    await hook({
      doc: { id: 11, email: 'nocontext@test.dev', identities: [] },
      operation: 'create',
      req: {
        payload: {
          update: (args: unknown) => {
            updates.push(args)
            return Promise.resolve()
          },
        },
      },
    })
    expect(updates).toHaveLength(0)
  })

  it('a wiring with no provider-owned-id port never writes', async () => {
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [createStubProvider().provider],
    })
    const hook = identityHookOf(options, createAuthLinkStrategy(options))
    const updates: unknown[] = []
    await hook({
      doc: { id: 9, email: 'x@test.dev', identities: [] },
      operation: 'create',
      req: {
        context: { [engineCreateMarker]: true },
        payload: {
          update: (args: unknown) => {
            updates.push(args)
            return Promise.resolve()
          },
        },
      },
    })
    expect(updates).toHaveLength(0)
  })
})

describe('withAdoptedCollectionHardening (GHSA-hfm3)', () => {
  type Logger = { readonly warns: string[] }
  function wiredWithLogger(): { options: ReturnType<typeof wireOptions>; logger: Logger } {
    const logger: Logger = { warns: [] }
    const { provider } = createStubProvider()
    const port: import('@payload-auth-link/core').LoggerPort = {
      debug: () => {},
      info: () => {},
      warn: (message: string) => {
        logger.warns.push(message)
      },
      error: () => {},
      child: () => port,
    }
    const options = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [provider],
      logger: port,
    })
    return { options, logger }
  }

  const hostCollections = (): CollectionConfig[] => [
    {
      slug: 'ba_sessions',
      access: { read: () => false },
      fields: [{ name: 'token', type: 'text' }],
      versions: { drafts: false },
    },
    {
      slug: 'ba_verifications',
      access: { read: () => false },
      fields: [{ name: 'value', type: 'text' }],
    },
    {
      slug: 'users',
      fields: [],
      versions: { drafts: false },
    },
    { slug: 'notes', fields: [{ name: 'title', type: 'text' }] },
  ]

  it('forces versions off and fills readVersions on adopted provider collections', () => {
    const { options } = wiredWithLogger()
    const hardened = withAdoptedCollectionHardening(
      hostCollections(),
      new Set(['ba_sessions', 'ba_verifications']),
      options
    )
    const sessions = hardened.find((collection) => collection.slug === 'ba_sessions')
    // The `versions: { drafts: false }` trap: still versioning. The fix
    // removes it outright — no copies are written and the /versions
    // routes disappear.
    expect(sessions?.versions).toBe(false)
    expect(typeof sessions?.access?.readVersions).toBe('function')
    const verifications = hardened.find((collection) => collection.slug === 'ba_verifications')
    expect(verifications?.versions).toBeUndefined()
    expect(typeof verifications?.access?.readVersions).toBe('function')
  })

  it('leaves the users slug alone — the plugin never passes it in this set', () => {
    // index.ts builds the adopted set with `slug !== usersCollection`
    // (withDefaultUserAccess governs users); the hardening itself is
    // generic over whatever it is given.
    const { options } = wiredWithLogger()
    const hardened = withAdoptedCollectionHardening(
      hostCollections(),
      new Set(['ba_sessions', 'ba_verifications']),
      options
    )
    const users = hardened.find((collection) => collection.slug === 'users')
    expect(users?.versions).toEqual({ drafts: false })
    expect(users?.access?.readVersions).toBeUndefined()
  })

  it('keeps the host’s own readVersions; untouched collections pass through', () => {
    const { options } = wiredWithLogger()
    const ownReadVersions = (): boolean => false
    const hardened = withAdoptedCollectionHardening(
      [
        {
          slug: 'ba_sessions',
          access: { read: () => false, readVersions: ownReadVersions },
          fields: [],
        },
        { slug: 'notes', fields: [] },
      ],
      new Set(['ba_sessions']),
      options
    )
    expect(hardened[0]?.access?.readVersions).toBe(ownReadVersions)
    expect(hardened[1]).toMatchObject({ slug: 'notes' })
  })

  it('no adopted slugs: the collections are returned unchanged', () => {
    const { options } = wiredWithLogger()
    const collections = hostCollections()
    const hardened = withAdoptedCollectionHardening(collections, new Set(), options)
    expect(hardened).toEqual(collections)
    expect(hardened).not.toBe(collections)
  })

  it('warns once naming each versioned slug', () => {
    const { options, logger } = wiredWithLogger()
    withAdoptedCollectionHardening(
      hostCollections(),
      new Set(['ba_sessions', 'ba_verifications', 'users']),
      options
    )
    expect(logger.warns).toHaveLength(1)
    expect(logger.warns[0]).toContain('ba_sessions')
    expect(logger.warns[0]).toContain('GHSA-hfm3')
    expect(logger.warns[0]).toContain('_v')
  })
})
