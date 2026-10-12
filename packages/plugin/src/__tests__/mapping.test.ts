import {
  defineProviderId,
  nullLogger,
  parseEmail,
  parseRole,
  systemClock,
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
    secret: 'x'.repeat(32),
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
})
