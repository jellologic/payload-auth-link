/**
 * Type-safe alarms (PLAN-UPGRADE-RESILIENCE Phase 3b, B16/B21).
 *
 * These pins exist to fail `tsc` — in CI, before release — when a
 * union, a boundary schema, or the Standard Schema surface drifts.
 * A failure here is never "fix the test": it means a human must
 * review the drift, update every consumer of the changed shape,
 * and only then update the pin in the same change.
 */
import type { StandardSchemaV1 } from '@standard-schema/spec'
import { describe, expect, expectTypeOf, it } from 'vitest'
import { emailSchema, type Email } from '../email.js'
import { linkingPolicySchema, type LinkingPolicy } from '../linking.js'
import { phoneNumberSchema, type PhoneNumber } from '../phone.js'
import {
  authMethods,
  providerIdSchema,
  sessionChannels,
  type AuthMethod,
  type Capability,
  type ProviderId,
  type SessionChannel,
} from '../ports.js'
import { roleSchema, type Role } from '../roles.js'
import {
  collectionMapSchema,
  startupConfigSchema,
  type CollectionMap,
  type StartupConfig,
} from '../validation.js'

describe('union inventories are pinned literal-for-literal', () => {
  it('pins AuthMethod and its single-source tuple', () => {
    expectTypeOf<AuthMethod>().toEqualTypeOf<
      | 'password'
      | 'magic-link'
      | 'email-otp'
      | 'oauth'
      | 'one-tap'
      | 'passkey'
      | 'phone-otp'
      | 'anonymous'
    >()
    expectTypeOf<(typeof authMethods)[number]>().toEqualTypeOf<AuthMethod>()
    expect(authMethods).toHaveLength(8)
  })

  it('pins SessionChannel and its single-source tuple', () => {
    expectTypeOf<SessionChannel>().toEqualTypeOf<'cookie' | 'bearer' | 'api-key' | 'device'>()
    expectTypeOf<(typeof sessionChannels)[number]>().toEqualTypeOf<SessionChannel>()
    expect(sessionChannels).toEqual(['cookie', 'bearer', 'api-key', 'device'])
  })

  it('pins Capability (adding one is an adapter-contract change)', () => {
    expectTypeOf<Capability>().toEqualTypeOf<
      | 'magic-link'
      | 'email-otp'
      | 'passkey'
      | 'oauth'
      | 'one-tap'
      | 'phone'
      | 'anonymous'
      | 'mfa'
      | 'impersonation'
      | 'revoke-user-sessions'
    >()
  })
})

describe('every exported Zod schema is a Standard Schema with matching types', () => {
  it('pins InferOutput to the domain type for each schema', () => {
    expectTypeOf<StandardSchemaV1.InferOutput<typeof emailSchema>>().toEqualTypeOf<Email>()
    expectTypeOf<
      StandardSchemaV1.InferOutput<typeof phoneNumberSchema>
    >().toEqualTypeOf<PhoneNumber>()
    expectTypeOf<StandardSchemaV1.InferOutput<typeof roleSchema>>().toEqualTypeOf<Role>()
    expectTypeOf<
      StandardSchemaV1.InferOutput<typeof providerIdSchema>
    >().toEqualTypeOf<ProviderId>()
    // LinkingPolicy is the schema output wrapped in Readonly — the
    // pin states that relationship exactly instead of pretending
    // the mutable schema output is the domain type.
    expectTypeOf<LinkingPolicy>().toEqualTypeOf<
      Readonly<StandardSchemaV1.InferOutput<typeof linkingPolicySchema>>
    >()
    expectTypeOf<
      StandardSchemaV1.InferOutput<typeof collectionMapSchema>
    >().toEqualTypeOf<CollectionMap>()
    expectTypeOf<
      StandardSchemaV1.InferOutput<typeof startupConfigSchema>
    >().toEqualTypeOf<StartupConfig>()
  })

  // The runtime half of the contract (B21): any Standard Schema
  // consumer (Effect, Valibot-era tooling, BA, Payload v4) must get
  // the same accept/reject answer Zod gives, or the boundary lies.
  const cases: readonly {
    readonly name: string
    readonly schema: StandardSchemaV1
    readonly accept: unknown
    readonly reject: unknown
  }[] = [
    { name: 'emailSchema', schema: emailSchema, accept: 'a@b.co', reject: 'not-an-email' },
    {
      name: 'phoneNumberSchema',
      schema: phoneNumberSchema,
      accept: '+15551234567',
      reject: '555-1234',
    },
    { name: 'roleSchema', schema: roleSchema, accept: 'admin', reject: 'Admin' },
    {
      name: 'providerIdSchema',
      schema: providerIdSchema,
      accept: 'better-auth',
      reject: 'Better Auth',
    },
    {
      name: 'linkingPolicySchema',
      schema: linkingPolicySchema,
      accept: { kind: 'verified-email' },
      reject: { kind: 'anything-goes' },
    },
    {
      name: 'collectionMapSchema',
      schema: collectionMapSchema,
      accept: {
        usersCollection: 'users',
        emailField: 'email',
        rolesField: 'roles',
        identitiesField: 'identities',
      },
      reject: { usersCollection: 'users' },
    },
    {
      name: 'startupConfigSchema',
      schema: startupConfigSchema,
      accept: {
        baseUrl: 'https://example.com',
        roles: ['user'],
        defaultRole: 'user',
        providers: ['better-auth'],
        map: {
          usersCollection: 'users',
          emailField: 'email',
          rolesField: 'roles',
          identitiesField: 'identities',
        },
      },
      reject: { baseUrl: 'not a url' },
    },
  ]

  for (const { name, schema, accept, reject } of cases) {
    it(`${name}: ~standard.validate agrees on accept and reject`, async () => {
      expect(schema['~standard'].version).toBe(1)
      expect(schema['~standard'].vendor).toBe('zod')
      const accepted = await schema['~standard'].validate(accept)
      expect(accepted.issues).toBeUndefined()
      const rejected = await schema['~standard'].validate(reject)
      expect(rejected.issues).toBeDefined()
      expect(rejected.issues?.length).toBeGreaterThan(0)
    })
  }
})
