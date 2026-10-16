/**
 * Property tests for the Better Auth → Payload `where` translation
 * (issue #86). The oracle for "same rows" is Better Auth's own
 * memoryAdapter semantics, re-stated here as a pure evaluator (a
 * left fold of every clause; the first clause's connector is
 * ignored), run against a pure evaluator of the translated Payload
 * `Where`. Unsupported shapes must throw `UnsupportedOperatorError` —
 * never be dropped from the query.
 */
import type { CleanedWhere } from 'better-auth/adapters'
import fc from 'fast-check'
import type { Where } from 'payload'
import { describe, expect, it } from 'vitest'
import { UnsupportedOperatorError } from '../errors.js'
import { translateWhereClause } from '../where.js'

const runs = { numRuns: 200 } as const

const fieldArb = fc.constantFrom('id', 'a', 'b')
const valueArb = fc.integer({ min: 0, max: 4 })
const connectorArb = fc.constantFrom<'AND' | 'OR'>('AND', 'OR')

/** Sensitive, non-null clauses: the shapes with a faithful translation. */
const supportedClauseArb: fc.Arbitrary<CleanedWhere> = fc.oneof(
  fc.record({
    field: fieldArb,
    operator: fc.constantFrom('eq', 'ne', 'lt', 'lte', 'gt', 'gte'),
    value: valueArb,
    connector: connectorArb,
    mode: fc.constant('sensitive'),
  }),
  fc.record({
    field: fieldArb,
    operator: fc.constantFrom('in', 'not_in'),
    value: fc.array(valueArb, { maxLength: 3 }),
    connector: connectorArb,
    mode: fc.constant('sensitive'),
  })
)

type Row = { id: number; a: number; b: number }
const rowArb: fc.Arbitrary<Row> = fc.record({ id: valueArb, a: valueArb, b: valueArb })

/** Better Auth memoryAdapter clause semantics (sensitive mode). */
function baEvalClause(row: Row, clause: CleanedWhere): boolean {
  const actual = row[clause.field as keyof Row]
  const value = clause.value as number | number[]
  switch (clause.operator) {
    case 'in':
      return (value as number[]).includes(actual)
    case 'not_in':
      return !(value as number[]).includes(actual)
    case 'ne':
      return actual !== value
    case 'gt':
      return actual > (value as number)
    case 'gte':
      return actual >= (value as number)
    case 'lt':
      return actual < (value as number)
    case 'lte':
      return actual <= (value as number)
    default:
      return actual === value
  }
}

/** memoryAdapter's fold: start from clause 0, then fold every clause by its connector. */
function baEval(row: Row, clauses: readonly CleanedWhere[]): boolean {
  const [first] = clauses
  if (first === undefined) {
    return true
  }
  let result = baEvalClause(row, first)
  for (const clause of clauses) {
    const next = baEvalClause(row, clause)
    result = clause.connector === 'OR' ? result || next : result && next
  }
  return result
}

/** A minimal evaluator of the Payload `Where` subset the translator emits. */
function payloadEval(row: Row, where: Where): boolean {
  return Object.entries(where).every(([key, condition]) => {
    if (key === 'and') {
      return (condition as Where[]).every((nested) => payloadEval(row, nested))
    }
    if (key === 'or') {
      return (condition as Where[]).some((nested) => payloadEval(row, nested))
    }
    const actual = row[(key === 'baId' ? 'id' : key) as keyof Row]
    return Object.entries(condition as Record<string, unknown>).every(([op, value]) => {
      switch (op) {
        case 'equals':
          return actual === value
        case 'not_equals':
          return actual !== value
        case 'less_than':
          return actual < (value as number)
        case 'less_than_equal':
          return actual <= (value as number)
        case 'greater_than':
          return actual > (value as number)
        case 'greater_than_equal':
          return actual >= (value as number)
        case 'in':
          return (value as number[]).includes(actual)
        case 'not_in':
          return !(value as number[]).includes(actual)
        case 'exists':
          return (actual !== null && actual !== undefined) === value
        default:
          throw new Error(`evaluator: unexpected Payload operator ${op}`)
      }
    })
  })
}

/** Every field key named anywhere in a translated `Where`. */
function fieldsOf(where: Where): Set<string> {
  const found = new Set<string>()
  for (const [key, condition] of Object.entries(where)) {
    if (key === 'and' || key === 'or') {
      for (const nested of condition as Where[]) {
        for (const field of fieldsOf(nested)) {
          found.add(field)
        }
      }
    } else {
      found.add(key)
    }
  }
  return found
}

describe('translateWhereClause (property)', () => {
  it('selects exactly the rows Better Auth would (memoryAdapter oracle)', () => {
    fc.assert(
      fc.property(
        fc.array(supportedClauseArb, { maxLength: 5 }),
        fc.array(rowArb, { maxLength: 8 }),
        (clauses, rows) => {
          const { where, postFilter } = translateWhereClause(clauses)
          expect(postFilter).toBeUndefined()
          for (const row of rows) {
            expect(payloadEval(row, where)).toBe(baEval(row, clauses))
          }
        }
      ),
      runs
    )
  })

  it('names exactly the clause fields (id → baId) and folds n clauses into n-1 connectors', () => {
    fc.assert(
      fc.property(fc.array(supportedClauseArb, { minLength: 1, maxLength: 6 }), (clauses) => {
        const { where } = translateWhereClause(clauses)
        const expected = new Set(
          clauses.map((clause) => (clause.field === 'id' ? 'baId' : clause.field))
        )
        expect(fieldsOf(where)).toEqual(expected)
        // Left-associative fold: each later clause adds exactly one
        // binary and/or node; the first clause's connector is inert.
        let depth = 0
        let node: Where = where
        while ('and' in node || 'or' in node) {
          const pair = (node.and ?? node.or) as Where[]
          expect(pair).toHaveLength(2)
          const [left] = pair
          if (left === undefined) {
            break
          }
          node = left
          depth += 1
        }
        // A leading `not_in` is itself an `or` pair (`NOT IN` OR null,
        // #110), one level below the fold.
        expect(depth).toBe(clauses.length - 1 + (clauses[0]?.operator === 'not_in' ? 1 : 0))
      }),
      runs
    )
  })

  it('refuses every pattern operator wherever it appears (never dropped)', () => {
    fc.assert(
      fc.property(
        fc.array(supportedClauseArb, { maxLength: 4 }),
        fc.nat(),
        fc.constantFrom('contains', 'starts_with', 'ends_with'),
        fc.constantFrom<'sensitive' | 'insensitive'>('sensitive', 'insensitive'),
        (clauses, at, operator, mode) => {
          const index = clauses.length === 0 ? 0 : at % (clauses.length + 1)
          const poisoned = [
            ...clauses.slice(0, index),
            { field: 'a', operator, value: 'x', connector: 'AND', mode } as CleanedWhere,
            ...clauses.slice(index),
          ]
          expect(() => translateWhereClause(poisoned)).toThrow(UnsupportedOperatorError)
        }
      ),
      runs
    )
  })

  it('refuses null with any operator but eq/ne, and insensitive non-equality', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('lt', 'lte', 'gt', 'gte', 'in', 'not_in'),
        fc.constantFrom('ne', 'in', 'not_in'),
        (rangeOperator, insensitiveOperator) => {
          expect(() =>
            translateWhereClause([
              {
                field: 'a',
                operator: rangeOperator,
                value: null,
                connector: 'AND',
                mode: 'sensitive',
              },
            ] as CleanedWhere[])
          ).toThrow(UnsupportedOperatorError)
          expect(() =>
            translateWhereClause([
              {
                field: 'a',
                operator: insensitiveOperator,
                value: insensitiveOperator === 'ne' ? 'x' : ['x'],
                connector: 'AND',
                mode: 'insensitive',
              },
            ] as CleanedWhere[])
          ).toThrow(UnsupportedOperatorError)
        }
      ),
      runs
    )
  })

  it('null eq/ne map to exists false/true', () => {
    fc.assert(
      fc.property(fieldArb, (field) => {
        const key = field === 'id' ? 'baId' : field
        expect(
          translateWhereClause([
            { field, operator: 'eq', value: null, connector: 'AND', mode: 'sensitive' },
          ] as CleanedWhere[]).where
        ).toEqual({ [key]: { exists: false } })
        expect(
          translateWhereClause([
            { field, operator: 'ne', value: null, connector: 'AND', mode: 'sensitive' },
          ] as CleanedWhere[]).where
        ).toEqual({ [key]: { exists: true } })
      }),
      runs
    )
  })

  it('insensitive eq: the post-filter is exact and case-blind when every connector is AND', () => {
    const word = fc.stringMatching(/^[A-Za-z]{1,6}$/)
    fc.assert(
      fc.property(
        word,
        word,
        fc.array(supportedClauseArb, { maxLength: 3 }),
        (wanted, other, rest) => {
          const clauses = [
            {
              field: 'email',
              operator: 'eq',
              value: wanted,
              connector: 'AND',
              mode: 'insensitive',
            },
            ...rest.map((clause) => ({ ...clause, connector: 'AND' as const })),
          ] as CleanedWhere[]
          const { postFilter } = translateWhereClause(clauses)
          expect(postFilter).toBeDefined()
          if (postFilter === undefined) {
            return
          }
          expect(postFilter({ email: wanted.toUpperCase() })).toBe(true)
          expect(postFilter({ email: wanted.toLowerCase() })).toBe(true)
          expect(postFilter({ email: `${wanted}${other}` })).toBe(false)
          expect(postFilter({ email: null })).toBe(false)
        }
      ),
      runs
    )
  })

  it('insensitive eq combined with any later OR connector is refused (post-filter cannot be exact)', () => {
    fc.assert(
      fc.property(
        fc.array(supportedClauseArb, { minLength: 1, maxLength: 4 }),
        fc.boolean(),
        (rest, insensitiveFirst) => {
          fc.pre(
            rest.some(
              (clause, index) => (insensitiveFirst ? true : index > 0) && clause.connector === 'OR'
            )
          )
          const insensitive = {
            field: 'email',
            operator: 'eq',
            value: 'Mixed@Case.dev',
            connector: 'AND',
            mode: 'insensitive',
          } as CleanedWhere
          const clauses = insensitiveFirst ? [insensitive, ...rest] : [...rest, insensitive]
          expect(() => translateWhereClause(clauses)).toThrow(UnsupportedOperatorError)
        }
      ),
      runs
    )
  })

  it('serialises Date values (scalar and in-list) to ISO strings', () => {
    fc.assert(
      fc.property(
        fc.date({ min: new Date(0), max: new Date(4_000_000_000_000), noInvalidDate: true }),
        (date) => {
          expect(
            translateWhereClause([
              {
                field: 'expiresAt',
                operator: 'gt',
                value: date,
                connector: 'AND',
                mode: 'sensitive',
              },
            ] as CleanedWhere[]).where
          ).toEqual({ expiresAt: { greater_than: date.toISOString() } })
          expect(
            translateWhereClause([
              {
                field: 'expiresAt',
                operator: 'in',
                value: [date],
                connector: 'AND',
                mode: 'sensitive',
              },
            ] as unknown as CleanedWhere[]).where
          ).toEqual({ expiresAt: { in: [date.toISOString()] } })
        }
      ),
      runs
    )
  })
})
