import {
  defineProviderId,
  nullLogger,
  parseEmail,
  parseRole,
  systemClock,
  type LoggerPort,
} from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import {
  firstResultRecord,
  toIdentityData,
  toNewUserData,
  toPayloadUser,
  toUserRecord,
  type MappingContext,
} from '../mapping.js'
import { wireOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

function ctx(): MappingContext {
  const { provider } = createStubProvider()
  const wired = wireOptions({
    baseUrl: 'http://auth-link.test',
    roles: ['admin', 'user'],
    defaultRole: 'user',
    providers: [provider],
  })
  return {
    map: wired.config.map,
    defaultRole: wired.config.defaultRole,
    logger: nullLogger(),
    clock: systemClock(),
  }
}

function role(value: string) {
  const parsed = parseRole(value)
  if (parsed.isErr()) {
    throw parsed.error
  }
  return parsed.value
}

const doc = () => ({
  id: 'user-1',
  email: 'Dev@Example.com',
  roles: ['admin', 'bogus role!!'],
  identities: [
    {
      providerId: 'stub',
      providerUserId: 'stub-1',
      email: 'dev@example.com',
      linkedAt: '2026-01-01T00:00:00.000Z',
    },
    { providerId: '', providerUserId: '', email: 'bad', linkedAt: 'never' },
  ],
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-02T00:00:00.000Z',
})

describe('degradation warnings (B20)', () => {
  it('warns once per kind per logger, however many rows are corrupt', () => {
    const warnings: string[] = []
    const base = nullLogger()
    const logger: LoggerPort = {
      ...base,
      warn: (message) => {
        warnings.push(message)
      },
      child: () => logger,
    }
    const context = { ...ctx(), logger }
    for (let index = 0; index < 5; index += 1) {
      toUserRecord(doc(), context)
    }
    // Five corrupt docs, one warning per distinct degradation kind.
    expect(warnings.length).toBeGreaterThan(0)
    expect(new Set(warnings).size).toBe(warnings.length)
    // A different logger (new composition root) warns again.
    const second: string[] = []
    const logger2: LoggerPort = {
      ...base,
      warn: (message) => {
        second.push(message)
      },
      child: () => logger2,
    }
    toUserRecord(doc(), { ...ctx(), logger: logger2 })
    expect(second).toEqual(warnings)
  })
})

describe('toUserRecord', () => {
  it('narrows a full doc, normalizing email and dropping bad parts', () => {
    const record = toUserRecord(doc(), ctx())
    expect(record?.id).toBe('user-1')
    expect(record?.email).toBe('dev@example.com')
    expect(record?.roles).toEqual(['admin'])
    expect(record?.identities).toHaveLength(1)
    expect(record?.identities[0]?.providerUserId).toBe('stub-1')
    expect(record?.createdAt).toBeInstanceOf(Date)
  })

  it('defaults missing roles and identities', () => {
    const record = toUserRecord(
      {
        id: 'user-2',
        email: 'a@b.co',
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
      ctx()
    )
    expect(record?.roles).toEqual(['user'])
    expect(record?.identities).toEqual([])
  })

  it('returns null for unmappable docs', () => {
    const context = ctx()
    expect(toUserRecord(null, context)).toBeNull()
    expect(toUserRecord({ ...doc(), id: '' }, context)).toBeNull()
    expect(toUserRecord({ ...doc(), email: 'bad' }, context)).toBeNull()
    expect(toUserRecord({ ...doc(), createdAt: 'never' }, context)).toBeNull()
  })

  it('denies defined-but-unmappable roles instead of upgrading to the default', () => {
    const context = ctx()
    // Emptied array, all-invalid entries, and a non-array are all
    // defined values that grant nothing: the record is denied, never
    // upgraded to the default role.
    expect(toUserRecord({ ...doc(), roles: [] }, context)).toBeNull()
    expect(toUserRecord({ ...doc(), roles: ['bogus role!!'] }, context)).toBeNull()
    expect(toUserRecord({ ...doc(), roles: 'admin' }, context)).toBeNull()
  })

  it('grandfathers undefined roles to the default for legacy docs', () => {
    const record = toUserRecord({ ...doc(), roles: undefined }, ctx())
    expect(record?.roles).toEqual(['user'])
  })
})

describe('configured-role membership (B11)', () => {
  function configuredCtx(configured: readonly string[]): MappingContext {
    return { ...ctx(), configuredRoles: new Set(configured.map(role)) }
  }

  it('drops stored roles outside the configured set at read time', () => {
    // Doc stores ['admin', 'editor']; config removed 'editor'.
    const record = toUserRecord({ ...doc(), roles: ['admin', 'editor'] }, configuredCtx(['admin']))
    expect(record?.roles).toEqual(['admin'])
  })

  it('warns once per removed role, naming it', () => {
    const warnings: string[] = []
    const base = nullLogger()
    const logger: LoggerPort = {
      ...base,
      warn: (message) => {
        warnings.push(message)
      },
      child: () => logger,
    }
    const context = { ...configuredCtx(['admin']), logger }
    for (let index = 0; index < 3; index += 1) {
      toUserRecord({ ...doc(), roles: ['admin', 'editor', 'owner'] }, context)
    }
    const editorWarnings = warnings.filter((message) => message.includes("'editor'"))
    const ownerWarnings = warnings.filter((message) => message.includes("'owner'"))
    expect(editorWarnings).toHaveLength(1)
    expect(ownerWarnings).toHaveLength(1)
  })

  it('denies the record when every stored role is unconfigured', () => {
    // Nothing stored grants anything configured: no default upgrade.
    const record = toUserRecord({ ...doc(), roles: ['editor'] }, configuredCtx(['admin']))
    expect(record).toBeNull()
  })

  it('leaves format-only narrowing for callers without the configured set', () => {
    const record = toUserRecord({ ...doc(), roles: ['admin', 'editor'] }, ctx())
    expect(record?.roles).toEqual(['admin', 'editor'])
  })
})

describe('firstResultRecord', () => {
  it('pulls the first doc or null', () => {
    const context = ctx()
    expect(firstResultRecord({ docs: [doc()] }, context)?.id).toBe('user-1')
    expect(firstResultRecord({ docs: [] }, context)).toBeNull()
    expect(firstResultRecord({}, context)).toBeNull()
  })
})

describe('writers', () => {
  it('builds create data and identity rows', () => {
    const context = ctx()
    const email = parseEmail('new@example.com')
    if (email.isErr()) {
      throw email.error
    }
    const data = toNewUserData(
      {
        email: email.value,
        roles: [role('user')],
        identity: { providerId: defineProviderId('stub'), providerUserId: 's-1' },
      },
      context,
      'random-password'
    )
    expect(data.email).toBe('new@example.com')
    expect(data.roles).toEqual(['user'])
    expect(data.identities).toHaveLength(1)

    const row = toIdentityData(
      { providerId: defineProviderId('stub'), providerUserId: 's-2' },
      'new@example.com',
      context.clock
    )
    expect(row.providerUserId).toBe('s-2')
  })

  it('builds the strategy user object', () => {
    const record = toUserRecord(doc(), ctx())
    if (!record) {
      throw new Error('fixture must map')
    }
    expect(toPayloadUser(record, 'users')).toEqual({
      id: 'user-1',
      collection: 'users',
      email: 'dev@example.com',
      roles: ['admin'],
    })
  })

  it('projects PORT-4 session facts only when present, copying them', () => {
    const record = toUserRecord(doc(), ctx())
    if (!record) {
      throw new Error('fixture must map')
    }
    const methods = ['password'] as const
    const projected = toPayloadUser(record, 'users', {
      assurance: { methods, mfa: true },
      actor: { kind: 'provider-only', providerUserId: 'operator-1' },
      organizationId: 'org-1',
    })
    expect(projected).toEqual({
      id: 'user-1',
      collection: 'users',
      email: 'dev@example.com',
      roles: ['admin'],
      assurance: { methods: ['password'], mfa: true },
      actor: { kind: 'provider-only', providerUserId: 'operator-1' },
      organizationId: 'org-1',
    })
    expect(projected.assurance?.methods).not.toBe(methods)
    // Absent facts stay absent — never nulls or fabricated defaults.
    const bare = toPayloadUser(record, 'users', {})
    expect(bare).not.toHaveProperty('assurance')
    expect(bare).not.toHaveProperty('actor')
    expect(bare).not.toHaveProperty('organizationId')
  })

  it("serializes 'unknown' assurance instead of dropping it", () => {
    const record = toUserRecord(doc(), ctx())
    if (!record) {
      throw new Error('fixture must map')
    }
    const projected = toPayloadUser(record, 'users', {
      assurance: { methods: 'unknown', mfa: 'unknown' },
    })
    expect(projected.assurance).toEqual({ methods: 'unknown', mfa: 'unknown' })
    expect(projected).not.toHaveProperty('actor')
  })
})

describe('MFA role projection (CAP-6)', () => {
  it('withholds gated roles and flags mfaRequired without MFA proof', () => {
    const record = toUserRecord(doc(), ctx())
    if (!record) {
      throw new Error('fixture must map')
    }
    const gated = [record.roles[0] as (typeof record.roles)[number]]
    const projected = toPayloadUser(
      record,
      'users',
      { assurance: { methods: 'unknown', mfa: 'unknown' } },
      { requireMfaForRoles: gated }
    )
    expect(projected.roles).toEqual([])
    expect(projected.mfaRequired).toBe(true)
    const proven = toPayloadUser(
      record,
      'users',
      { assurance: { methods: ['password'], mfa: true } },
      { requireMfaForRoles: gated }
    )
    expect(proven.roles).toEqual(['admin'])
    expect(proven).not.toHaveProperty('mfaRequired')
  })

  it('maps phone and suspension fields, failing closed on a bad suspension date', () => {
    const record = toUserRecord(
      {
        ...doc(),
        phone: '+14155550132',
        suspendedUntil: '2030-01-01T00:00:00.000Z',
        suspendReason: 'abuse',
      },
      ctx()
    )
    expect(record?.phone).toBe('+14155550132')
    expect(record?.suspendedUntil?.toISOString()).toBe('2030-01-01T00:00:00.000Z')
    expect(record?.suspendReason).toBe('abuse')
    expect(toUserRecord({ ...doc(), suspendedUntil: 'not-a-date' }, ctx())).toBeNull()
    expect(toUserRecord({ ...doc(), phone: '555-0132' }, ctx())?.phone).toBeNull()
  })
})
