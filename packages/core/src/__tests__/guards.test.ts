import { describe, expect, it } from 'vitest'
import { isNonEmptyString, isRecord, toDate } from '../guards.js'

describe('isRecord', () => {
  it('narrows plain objects and rejects the rest', () => {
    expect(isRecord({ a: 1 })).toBe(true)
    expect(isRecord(null)).toBe(false)
    expect(isRecord('x')).toBe(false)
    expect(isRecord(42)).toBe(false)
    expect(isRecord(undefined)).toBe(false)
  })
})

describe('isNonEmptyString', () => {
  it('accepts non-empty strings only', () => {
    expect(isNonEmptyString('x')).toBe(true)
    expect(isNonEmptyString('')).toBe(false)
    expect(isNonEmptyString(42)).toBe(false)
    expect(isNonEmptyString(null)).toBe(false)
  })
})

describe('toDate', () => {
  it('passes valid dates through and rejects NaN dates', () => {
    const valid = new Date('2026-01-01T00:00:00.000Z')
    expect(toDate(valid)).toBe(valid)
    expect(toDate(new Date('nope'))).toBeNull()
  })

  it('coerces ISO strings and epoch numbers, rejects the rest', () => {
    expect(toDate('2026-01-01T00:00:00.000Z')).toEqual(new Date('2026-01-01T00:00:00.000Z'))
    expect(toDate(0)).toEqual(new Date(0))
    expect(toDate('nope')).toBeNull()
    expect(toDate(null)).toBeNull()
    expect(toDate({})).toBeNull()
  })
})
