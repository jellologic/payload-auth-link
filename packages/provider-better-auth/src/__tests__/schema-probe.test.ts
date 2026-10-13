/**
 * Committed Better Auth schema probe (PLAN-CAPABILITIES Phase 1): every
 * BA plugin named in the plan that the installed `better-auth` package
 * exports is composed into one real engine on real Payload storage
 * (SQLite in memory). The `customFields` / `customModels` declarations
 * are GENERATED from BA's own `getAuthTables` output — never hand-copied
 * — so the engine only boots if every plugin field and model maps onto
 * a Payload column this adapter can serve.
 *
 * Drift alarm: the generated declaration inventory is also compared
 * against the pinned inventory below. Any BA schema change (field or
 * model added, removed, renamed, retyped) fails this test until a human
 * reviews the change and updates the pin. Unsupported BA field types
 * fail generation outright.
 *
 * Satellites are devDependencies and probed like first-party plugins:
 * passkey (since CAP-5) and api-key (`@better-auth/api-key`, verified
 * working when declared — issue #16). Skipped: sso
 * (`@better-auth/sso`) — still not a dependency here. Teams are
 * covered via `organization({ teams: { enabled: true } })`.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { apiKey } from '@better-auth/api-key'
import { passkey } from '@better-auth/passkey'
import { getAuthTables } from 'better-auth/db'
import {
  admin,
  anonymous,
  emailOTP,
  genericOAuth,
  magicLink,
  multiSession,
  oneTap,
  organization,
  phoneNumber,
  siwe,
  twoFactor,
  username,
} from 'better-auth/plugins'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'
import { generateDeclarations, isCoreModel, payloadOwnedFields } from './declarations.js'

const ORIGIN = 'http://schema-probe.test'
const SECRET = 'schema-probe-integration-secret!!!'

const probePlugins = [
  organization({ teams: { enabled: true } }),
  admin(),
  // @better-auth/api-key (a satellite, like passkey): verified working
  // when declared (issue #16) — probed so it stays true across BA bumps.
  apiKey({ defaultPrefix: 'bock_', enableMetadata: true, enableSessionForAPIKeys: true }),
  anonymous(),
  phoneNumber({ sendOTP: () => Promise.resolve() }),
  magicLink({ sendMagicLink: () => Promise.resolve() }),
  emailOTP({ sendVerificationOTP: () => Promise.resolve() }),
  genericOAuth({ config: [] }),
  oneTap({ clientId: 'schema-probe-client' }),
  twoFactor(),
  passkey({ rpID: 'schema-probe.test', rpName: 'Schema Probe', origin: ORIGIN }),
  username(),
  siwe({
    domain: 'schema-probe.test',
    getNonce: () => Promise.resolve('probe-nonce'),
    verifyMessage: () => Promise.resolve(true),
  }),
  multiSession(),
]

const probeOptions = {
  baseURL: ORIGIN,
  trustedOrigins: [ORIGIN],
  secret: SECRET,
  emailAndPassword: { enabled: true, requireEmailVerification: false },
  rateLimit: { enabled: true, storage: 'database' as const },
  plugins: probePlugins,
}

type ProbeTables = ReturnType<typeof getAuthTables>
type ProbeTable = ProbeTables[string]
type ProbeAttribute = ProbeTable['fields'][string]

// Declaration generation lives in ./declarations.ts (shared with
// the capabilities integration tests).

/** One sorted `model.field:type[:required][:unique]` line per BA field. */
function inventoryOf(tables: ProbeTables): string[] {
  const lines: string[] = []
  for (const [model, table] of Object.entries(tables)) {
    for (const [field, attribute] of Object.entries(table.fields)) {
      lines.push(
        `${model}.${field}:${String(attribute.type)}` +
          `${attribute.required === true ? ':required' : ''}` +
          `${attribute.unique === true ? ':unique' : ''}`
      )
    }
  }
  return lines.sort()
}

/**
 * The pinned BA 1.7.7 inventory for the plugin set above. A diff here
 * means a BA upgrade changed a plugin schema: review the new fields,
 * confirm the adapter serves them (this probe's round-trips), then
 * update the pin in the same change.
 */
const pinnedInventory: readonly string[] = [
  'account.accessToken:string',
  'account.accessTokenExpiresAt:date',
  'account.accountId:string:required',
  'account.createdAt:date:required',
  'account.idToken:string',
  'account.password:string',
  'account.providerId:string:required',
  'account.refreshToken:string',
  'account.refreshTokenExpiresAt:date',
  'account.scope:string',
  'account.updatedAt:date:required',
  'account.userId:string:required',
  'apikey.configId:string:required',
  'apikey.createdAt:date:required',
  'apikey.enabled:boolean',
  'apikey.expiresAt:date',
  'apikey.key:string:required',
  'apikey.lastRefillAt:date',
  'apikey.lastRequest:date',
  'apikey.metadata:string',
  'apikey.name:string',
  'apikey.permissions:string',
  'apikey.prefix:string',
  'apikey.rateLimitEnabled:boolean',
  'apikey.rateLimitMax:number',
  'apikey.rateLimitTimeWindow:number',
  'apikey.referenceId:string:required',
  'apikey.refillAmount:number',
  'apikey.refillInterval:number',
  'apikey.remaining:number',
  'apikey.requestCount:number',
  'apikey.start:string',
  'apikey.updatedAt:date:required',
  'invitation.createdAt:date:required',
  'invitation.email:string:required',
  'invitation.expiresAt:date:required',
  'invitation.inviterId:string:required',
  'invitation.organizationId:string:required',
  'invitation.role:string',
  'invitation.status:string:required',
  'invitation.teamId:string',
  'member.createdAt:date:required',
  'member.organizationId:string:required',
  'member.role:string:required',
  'member.userId:string:required',
  'organization.createdAt:date:required',
  'organization.logo:string',
  'organization.metadata:string',
  'organization.name:string:required',
  'organization.slug:string:required:unique',
  'passkey.aaguid:string',
  'passkey.backedUp:boolean:required',
  'passkey.counter:number:required',
  'passkey.createdAt:date',
  'passkey.credentialID:string:required',
  'passkey.deviceType:string:required',
  'passkey.name:string',
  'passkey.publicKey:string:required',
  'passkey.transports:string',
  'passkey.userId:string:required',
  'rateLimit.count:number:required',
  'rateLimit.key:string:required:unique',
  'rateLimit.lastRequest:number:required',
  'session.activeOrganizationId:string',
  'session.activeTeamId:string',
  'session.createdAt:date:required',
  'session.expiresAt:date:required',
  'session.impersonatedBy:string',
  'session.ipAddress:string',
  'session.token:string:required:unique',
  'session.updatedAt:date:required',
  'session.userAgent:string',
  'session.userId:string:required',
  'team.createdAt:date:required',
  'team.memberCount:number:required',
  'team.name:string:required',
  'team.organizationId:string:required',
  'team.updatedAt:date',
  'teamMember.createdAt:date',
  'teamMember.membershipKey:string:unique',
  'teamMember.teamId:string:required',
  'teamMember.userId:string:required',
  'twoFactor.backupCodes:string:required',
  'twoFactor.failedVerificationCount:number',
  'twoFactor.lockedUntil:date',
  'twoFactor.secret:string:required',
  'twoFactor.userId:string:required',
  'twoFactor.verified:boolean',
  'user.banExpires:date',
  'user.banReason:string',
  'user.banned:boolean',
  'user.createdAt:date:required',
  'user.displayUsername:string',
  'user.email:string:required:unique',
  'user.emailVerified:boolean:required',
  'user.image:string',
  'user.isAnonymous:boolean',
  'user.name:string:required',
  'user.phoneNumber:string:unique',
  'user.phoneNumberVerified:boolean',
  'user.role:string',
  'user.twoFactorEnabled:boolean',
  'user.updatedAt:date:required',
  'user.username:string:unique',
  'verification.createdAt:date:required',
  'verification.expiresAt:date:required',
  'verification.identifier:string:required',
  'verification.updatedAt:date:required',
  'verification.value:string:required',
  'walletAddress.address:string:required',
  'walletAddress.chainId:number:required',
  'walletAddress.createdAt:date:required',
  'walletAddress.isPrimary:boolean',
  'walletAddress.userId:string:required',
]

const tables = getAuthTables(probeOptions)
const declarations = generateDeclarations(tables)

let latePayload: Payload | undefined
const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  customFields: declarations.customFields,
  customModels: declarations.customModels,
  options: probeOptions,
})

beforeAll(async () => {
  const config: SanitizedConfig = await buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    db: sqliteAdapter({ client: { url: ':memory:' } }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
  })
  latePayload = await getPayload({ config })
  // Booting the context runs the adapter's schema validation against
  // the generated declarations: any undeclared or unmappable plugin
  // field/model fails here, before a single test body runs.
  await engine.auth.$context
}, 120_000)

const probeDate = new Date('2027-06-01T12:00:00.000Z')

/**
 * A minimal valid value per BA attribute type. Strings are lowercase and
 * field-scoped: several plugin fields are unique, `user.email` is a
 * Payload `email` column, and the username plugin lowercases on input.
 */
function probeValue(model: string, field: string, attribute: ProbeAttribute): unknown {
  switch (attribute.type) {
    case 'string':
      return field === 'email' ? `${model}@schema-probe.test` : `probe-${model}-${field}`
    case 'number':
      return 7
    case 'boolean':
      return true
    case 'date':
      return probeDate
    case 'json':
      return { probe: `${model}.${field}` }
    default:
      throw new Error(
        `schema probe: no probe value for ${model}.${field} (${JSON.stringify(attribute.type)})`
      )
  }
}

describe('BA schema probe: pinned inventory', () => {
  it('matches the pinned BA 1.7.7 plugin schema inventory', () => {
    expect(inventoryOf(tables)).toEqual([...pinnedInventory])
  })

  it('declares every non-core model and core-model plugin field', () => {
    const declaredModels = declarations.customModels.map((entry) => entry.model).sort()
    expect(declaredModels).toEqual(
      Object.keys(tables)
        .filter((model) => !isCoreModel(model))
        .sort()
    )
    // The composed plugins must actually contribute plugin fields to
    // core models; an empty map would mean the plugins were dropped.
    expect(Object.keys(declarations.customFields).sort()).toEqual(['session', 'user'])
  })

  it.skip('passkey: lives in @better-auth/passkey, not a dependency here (lands with CAP-5)', () => {})
  it.skip('sso: lives in @better-auth/sso, not exported by better-auth 1.7.7', () => {})
})

describe('BA schema probe: per-model round-trip on Payload storage', () => {
  for (const [model, table] of Object.entries(tables)) {
    it(`round-trips every declared field of model "${model}"`, async () => {
      const ctx = await engine.auth.$context
      const data: Record<string, unknown> = {}
      for (const [field, attribute] of Object.entries(table.fields)) {
        if (payloadOwnedFields.has(field)) {
          continue
        }
        data[field] = probeValue(model, field, attribute)
      }
      const created = await ctx.adapter.create<Record<string, unknown>>({ model, data })
      const createdId = created.id
      if (typeof createdId !== 'string' || createdId === '') {
        throw new Error(`schema probe: ${model} create returned no string id`)
      }

      const found = await ctx.adapter.findOne<Record<string, unknown>>({
        model,
        where: [{ field: 'id', value: createdId }],
      })
      expect(found).not.toBeNull()
      for (const [field, value] of Object.entries(data)) {
        expect(found?.[field], `${model}.${field}`).toEqual(value)
      }
      expect(await ctx.adapter.count({ model })).toBeGreaterThan(0)
    })
  }
})

describe('BA schema probe: composed engine', () => {
  it('serves an email/password sign-up with every probe plugin composed', async () => {
    const signup = await engine.auth.handler(
      new Request(`${ORIGIN}/api/auth/sign-up/email`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({
          name: 'Probe User',
          email: 'signup@schema-probe.test',
          password: 'correct-horse-battery',
        }),
      })
    )
    expect(signup.status).toBe(200)
  })
})
