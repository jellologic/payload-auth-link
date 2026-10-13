import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { apiKey } from '@better-auth/api-key'
import { admin, anonymous, organization } from 'better-auth/plugins'
import { createBetterAuthEngine, mergeDeclarations } from '../engine.js'
import { declarationsFromTables, deriveBetterAuthSchema } from '../derive-schema.js'

const ORIGIN = 'http://derive.test'

describe('declarationsFromTables (pure derivation)', () => {
  it('maps types, drops Payload-owned fields and core-table fields', () => {
    const tables = {
      user: {
        modelName: 'user',
        fields: {
          id: { type: 'string', required: true, fieldName: 'id' },
          createdAt: { type: 'date', required: true },
          email: { type: 'string', required: true, unique: true },
          // plugin-added core field
          role: { type: 'string' },
        },
      },
      member: {
        modelName: 'member',
        fields: {
          createdAt: { type: 'date', required: true },
          organizationId: { type: 'string', required: true },
          role: { type: 'string', required: true, defaultValue: 'member' },
        },
      },
    } as never
    const { customFields, customModels } = declarationsFromTables(tables)
    // Core model: only plugin-added fields, id/createdAt/base email dropped.
    expect(customFields.user?.map((field) => field.name)).toEqual(['role'])
    // Custom model: Payload-owned dropped; defaultValue defers required.
    const member = customModels[0]
    expect(member?.model).toBe('member')
    expect(member?.fields.map((field) => field.name)).toEqual(['organizationId', 'role'])
    const role = member?.fields.find((field) => field.name === 'role')
    expect(role?.required).toBeUndefined()
  })

  it('maps arrays and unknowns to json and defers unique on json', () => {
    const tables = {
      widget: {
        modelName: 'widget',
        fields: {
          tags: { type: 'string[]' },
          payload: { type: 'json', unique: true },
          when: { type: 'date', unique: true },
        },
      },
    } as never
    const { customModels } = declarationsFromTables(tables)
    const fields = customModels[0]?.fields ?? []
    expect(fields.find((field) => field.name === 'tags')?.type).toBe('json')
    const json = fields.find((field) => field.name === 'payload')
    expect(json?.type).toBe('json')
    expect(json?.unique).toBeUndefined()
    expect(fields.find((field) => field.name === 'when')?.unique).toBe(true)
  })

  it('throws on model renames instead of declaring a table BA never queries', () => {
    const tables = {
      member: { modelName: 'org_member', fields: {} },
    } as never
    expect(() => declarationsFromTables(tables)).toThrow(/renamed/)
  })
})

describe('deriveBetterAuthSchema (live getAuthTables)', () => {
  const derived = deriveBetterAuthSchema({
    baseURL: ORIGIN,
    secret: 'x'.repeat(32),
    user: {
      additionalFields: {
        role: { type: 'string', required: true, defaultValue: 'user', input: true },
      },
    },
    plugins: [organization(), admin(), anonymous(), apiKey({ enableSessionForAPIKeys: true })],
  })

  it('derives every non-core model of the composed plugin set', () => {
    const models = derived.customModels.map((entry) => entry.model).sort()
    expect(models).toEqual(
      [
        'apikey',
        'invitation',
        'member',
        'organization',
        'session-impersonation' in {} ? 'session' : 'session',
      ].filter((m) => ['apikey', 'invitation', 'member', 'organization'].includes(m))
    )
  })

  it('derives core-model plugin fields (admin + api-key + anonymous + additional)', () => {
    const userFields = derived.customFields.user?.map((field) => field.name).sort()
    // admin: banned/banReason/banExpires; anonymous: isAnonymous;
    // builder: role.
    expect(userFields).toEqual(['banExpires', 'banReason', 'banned', 'isAnonymous', 'role'])
    expect(derived.customFields.session?.map((field) => field.name)).toContain(
      'activeOrganizationId'
    )
  })

  it('excludes Payload-owned timestamps everywhere', () => {
    for (const entry of derived.customModels) {
      expect(entry.fields.some((field) => field.name === 'createdAt')).toBe(false)
      expect(entry.fields.some((field) => field.name === 'updatedAt')).toBe(false)
    }
  })
})

describe('mergeDeclarations', () => {
  it('builder entries win; derived fills the gaps', () => {
    const merged = mergeDeclarations(
      {
        options: {
          baseURL: ORIGIN,
          secret: 'x'.repeat(32),
          plugins: [organization(), apiKey({ enableSessionForAPIKeys: true })],
        },
        customFields: {
          user: [{ name: 'role', type: 'text', required: true }],
        },
        customModels: [],
        autoDeclare: true,
      },
      true
    )
    // Derived organization model present without a hand declaration.
    expect(merged.customModels.map((entry) => entry.model)).toContain('organization')
    // The builder's role field survived the merge (derived has none).
    expect(merged.customFields.user?.some((field) => field.name === 'role')).toBe(true)
  })

  it('without autoDeclare, only the builder declarations are served (copied)', () => {
    const builderModel = {
      model: 'twoFactor',
      fields: [{ name: 'secret', type: 'text' as const, required: true }],
    }
    const merged = mergeDeclarations(
      {
        options: { baseURL: ORIGIN, secret: 'x'.repeat(32), plugins: [organization()] },
        customFields: {},
        customModels: [builderModel],
        autoDeclare: false,
      },
      false
    )
    expect(merged.customModels.map((entry) => entry.model)).toEqual(['twoFactor'])
    expect(merged.customModels[0]).not.toBe(builderModel)
  })
})

describe('autoDeclare engine boot', () => {
  let config: SanitizedConfig
  let payload: Payload

  beforeAll(async () => {
    // The engine resolves Payload lazily, so the collections-only
    // pass needs no instance; the wired engine below gets the real one.
    const options = {
      baseURL: ORIGIN,
      secret: 'x'.repeat(32),
      plugins: [organization(), admin(), apiKey({ enableSessionForAPIKeys: true })],
    }
    const collectionsEngine = createBetterAuthEngine({
      autoDeclare: true,
      getPayload: () => Promise.reject(new Error('collections only')),
      options,
    })
    config = await buildConfig({
      secret: 'auto-declare-secret!!',
      serverURL: ORIGIN,
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      telemetry: false,
      logger: { options: { level: 'silent' } },
      collections: [{ slug: 'users', auth: true, fields: [] }, ...collectionsEngine.collections],
    })
    payload = await getPayload({ config })
    const wired = createBetterAuthEngine({
      autoDeclare: true,
      getPayload: () => Promise.resolve(payload),
      options,
    })
    // Schema validation runs here: every derived model/field must be
    // declared and servable, or the context rejects.
    await wired.auth.$context
  }, 120_000)

  afterAll(async () => {
    await payload.db.destroy?.()
  })

  it('boots with zero hand declarations and serves the derived models', async () => {
    const wired = createBetterAuthEngine({
      autoDeclare: true,
      getPayload: () => Promise.resolve(payload),
      options: {
        baseURL: ORIGIN,
        secret: 'x'.repeat(32),
        plugins: [organization(), admin(), apiKey({ enableSessionForAPIKeys: true })],
      },
    })
    const ctx = await wired.auth.$context
    const created = await ctx.adapter.create({
      model: 'organization',
      data: { name: 'Derived Co', slug: 'derived-co' },
    })
    expect(created).toMatchObject({ slug: 'derived-co' })
  })
})
