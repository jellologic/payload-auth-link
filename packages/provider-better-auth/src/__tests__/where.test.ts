import type { CleanedWhere } from 'better-auth/adapters'
import { describe, expect, it } from 'vitest'
import { UnsupportedOperatorError } from '../errors.js'
import { baFieldToPayload, translateWhereClause } from '../where.js'

function clause(overrides: Partial<CleanedWhere> & { field: string }): CleanedWhere {
  return {
    operator: 'eq',
    value: 'x',
    connector: 'AND',
    mode: 'sensitive',
    ...overrides,
  }
}

describe('baFieldToPayload', () => {
  it('maps id to baId and leaves other fields alone', () => {
    expect(baFieldToPayload('id')).toBe('baId')
    expect(baFieldToPayload('email')).toBe('email')
    expect(baFieldToPayload('token')).toBe('token')
  })
})

describe('translateWhereClause', () => {
  it('translates an empty clause list to an empty where', () => {
    const { where, postFilter } = translateWhereClause([])
    expect(where).toEqual({})
    expect(postFilter).toBeUndefined()
  })

  it('translates comparison operators', () => {
    expect(translateWhereClause([clause({ field: 'email', value: 'a@b.c' })]).where).toEqual({
      email: { equals: 'a@b.c' },
    })
    expect(
      translateWhereClause([clause({ field: 'email', operator: 'ne', value: 'a@b.c' })]).where
    ).toEqual({ email: { not_equals: 'a@b.c' } })
    expect(translateWhereClause([clause({ field: 'n', operator: 'gt', value: 3 })]).where).toEqual({
      n: { greater_than: 3 },
    })
    expect(translateWhereClause([clause({ field: 'n', operator: 'lte', value: 3 })]).where).toEqual(
      { n: { less_than_equal: 3 } }
    )
    expect(
      translateWhereClause([clause({ field: 'id', operator: 'in', value: ['a', 'b'] })]).where
    ).toEqual({ baId: { in: ['a', 'b'] } })
    expect(
      translateWhereClause([clause({ field: 'id', operator: 'not_in', value: ['a'] })]).where
    ).toEqual({ or: [{ baId: { not_in: ['a'] } }, { baId: { exists: false } }] })
  })

  it('translates the remaining range operators', () => {
    expect(translateWhereClause([clause({ field: 'n', operator: 'lt', value: 3 })]).where).toEqual({
      n: { less_than: 3 },
    })
    expect(translateWhereClause([clause({ field: 'n', operator: 'gte', value: 3 })]).where).toEqual(
      { n: { greater_than_equal: 3 } }
    )
  })

  it('serializes Date arrays element-wise', () => {
    // `CleanedWhere` types `in` values as `(string|number)[]`; the cast
    // proves the runtime still serializes Dates if one ever arrives.
    const days = [new Date('2026-01-02T00:00:00.000Z'), new Date('2026-01-03T00:00:00.000Z')]
    const value = days as unknown as string[]
    expect(
      translateWhereClause([clause({ field: 'expiresAt', operator: 'in', value })]).where
    ).toEqual({ expiresAt: { in: ['2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z'] } })
  })

  it('throws on null with a non-equality operator', () => {
    expect(() =>
      translateWhereClause([clause({ field: 'image', operator: 'gt', value: null })])
    ).toThrow(UnsupportedOperatorError)
  })

  it('throws on case-insensitive equality over non-strings', () => {
    expect(() =>
      translateWhereClause([clause({ field: 'n', value: 3, mode: 'insensitive' })])
    ).toThrow(UnsupportedOperatorError)
  })

  it('maps id lookups to baId', () => {
    expect(translateWhereClause([clause({ field: 'id', value: 'ba-1' })]).where).toEqual({
      baId: { equals: 'ba-1' },
    })
  })

  it('serializes Date values to ISO strings', () => {
    const at = new Date('2026-01-02T03:04:05.000Z')
    expect(translateWhereClause([clause({ field: 'expiresAt', value: at })]).where).toEqual({
      expiresAt: { equals: '2026-01-02T03:04:05.000Z' },
    })
  })

  it('maps null equality to existence checks', () => {
    expect(translateWhereClause([clause({ field: 'image', value: null })]).where).toEqual({
      image: { exists: false },
    })
    expect(
      translateWhereClause([clause({ field: 'image', operator: 'ne', value: null })]).where
    ).toEqual({ image: { exists: true } })
  })

  it('folds mixed connectors left-associatively', () => {
    const { where } = translateWhereClause([
      clause({ field: 'a', value: '1' }),
      clause({ field: 'b', value: '2', connector: 'OR' }),
      clause({ field: 'c', value: '3', connector: 'AND' }),
    ])
    expect(where).toEqual({
      and: [{ or: [{ a: { equals: '1' } }, { b: { equals: '2' } }] }, { c: { equals: '3' } }],
    })
  })

  it('exact-matches case-insensitive equality with a post-filter', () => {
    const { where, postFilter } = translateWhereClause([
      clause({ field: 'email', value: 'A@B.C', mode: 'insensitive' }),
    ])
    // Symbols split the narrowing into words (LIKE/regex-safe).
    expect(where).toEqual({ email: { like: 'A B C' } })
    expect(postFilter).toBeDefined()
    expect(postFilter?.({ email: 'a@b.c' })).toBe(true)
    expect(postFilter?.({ email: 'a@b.cx' })).toBe(false)
    expect(postFilter?.({ email: 42 })).toBe(false)
  })

  it('narrows non-ASCII case-insensitive equality on ASCII fragments only (#110)', () => {
    const narrowed = (value: string) =>
      translateWhereClause([clause({ field: 'name', value, mode: 'insensitive' })]).where
    // SQLite LIKE folds ASCII only: non-ASCII letters never reach it.
    expect(narrowed('ÄRGER')).toEqual({ name: { like: 'RGER' } })
    expect(narrowed('Straße Müller')).toEqual({ name: { like: 'Stra e M ller' } })
    // i/k are what İ and the Kelvin sign lowercase to: never narrowed on.
    expect(narrowed('Kiki')).toEqual({ name: { exists: true } })
    expect(narrowed('ÄÖÜ')).toEqual({ name: { exists: true } })
    expect(narrowed('100%_x')).toEqual({ name: { like: '100 x' } })
    const { postFilter } = translateWhereClause([
      clause({ field: 'name', value: 'ÄRGER', mode: 'insensitive' }),
    ])
    expect(postFilter?.({ name: 'ärger' })).toBe(true)
    expect(postFilter?.({ name: 'Ärger' })).toBe(true)
    expect(postFilter?.({ name: 'ärgerlich' })).toBe(false)
  })

  it('throws on pattern operators', () => {
    for (const operator of ['contains', 'starts_with', 'ends_with'] as const) {
      expect(() => translateWhereClause([clause({ field: 'email', operator })])).toThrow(
        UnsupportedOperatorError
      )
    }
  })

  it('throws on case-insensitive non-equality', () => {
    expect(() =>
      translateWhereClause([clause({ field: 'email', operator: 'ne', mode: 'insensitive' })])
    ).toThrow(UnsupportedOperatorError)
    expect(() =>
      translateWhereClause([
        clause({ field: 'id', operator: 'in', value: ['a'], mode: 'insensitive' }),
      ])
    ).toThrow(UnsupportedOperatorError)
  })

  it('refuses case-insensitive equality under an OR connector (post-filter would drop rows)', () => {
    expect(() =>
      translateWhereClause([
        clause({ field: 'email', value: 'A@B.C', mode: 'insensitive' }),
        clause({ field: 'name', value: 'x', connector: 'OR' }),
      ])
    ).toThrow(UnsupportedOperatorError)
    expect(() =>
      translateWhereClause([
        clause({ field: 'name', value: 'x' }),
        clause({ field: 'email', value: 'A@B.C', mode: 'insensitive', connector: 'OR' }),
      ])
    ).toThrow(UnsupportedOperatorError)
    // The first clause's connector is not a combinator: an insensitive
    // eq that is AND-ed with everything stays translatable.
    const { postFilter } = translateWhereClause([
      clause({ field: 'email', value: 'A@B.C', mode: 'insensitive', connector: 'OR' }),
      clause({ field: 'name', value: 'x' }),
    ])
    expect(postFilter).toBeDefined()
  })

  it('applies documented defaults for undefined operator, connector, and mode', () => {
    const { where } = translateWhereClause([
      {
        field: 'email',
        value: 'a@b.c',
        operator: undefined,
        connector: undefined,
        mode: undefined,
      },
    ])
    expect(where).toEqual({ email: { equals: 'a@b.c' } })
  })
})
