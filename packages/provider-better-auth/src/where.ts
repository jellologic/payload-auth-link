import { assertNever } from '@payload-auth-link/core'
import type { Where } from 'payload'
import type { CleanedWhere } from 'better-auth/adapters'
import { UnsupportedOperatorError } from './errors.js'

/**
 * Better Auth addresses rows by `id`; Payload owns the document `id`, so the
 * adapter persists the provider id in `baId`. Every other field maps 1:1 —
 * the adapter rejects renamed models/fields at startup, so physical names
 * always equal the canonical Better Auth names here. Adopted models
 * (issue #49) pass a per-model resolver instead: `id` resolves to the
 * document `id` under `idStrategy: 'payload'`, and renamed fields
 * resolve through the schema map.
 */
export function baFieldToPayload(field: string): string {
  return field === 'id' ? 'baId' : field
}

/** Per-model field resolution for adopted models (see baFieldToPayload). */
export type FieldResolver = (field: string) => string

/**
 * Payload `Where` values must be JSON: `Date` instances become ISO strings.
 * Arrays map element-wise (`in`/`not_in`); anything else passes through.
 * `coerceValue` lets adopted models retype id values (a numeric Payload
 * relationship wants a number where Better Auth hands over a string).
 */
function toPayloadValue(
  value: unknown,
  coerceValue?: (field: string, value: unknown) => unknown,
  field?: string
): unknown {
  const coerced =
    coerceValue !== undefined && field !== undefined ? coerceValue(field, value) : value
  if (coerced instanceof Date) {
    return coerced.toISOString()
  }
  if (Array.isArray(coerced)) {
    const entries: unknown[] = coerced
    return entries.map((entry) => (entry instanceof Date ? entry.toISOString() : entry))
  }
  return coerced
}

function clauseToWhere(
  clause: CleanedWhere,
  mapField?: FieldResolver,
  coerceValue?: (field: string, value: unknown) => unknown
): {
  where: Where
  postFilter?: (row: Record<string, unknown>) => boolean
} {
  // `CleanedWhere` still types the documented defaults as possibly
  // undefined; the factory guarantees them, so defaulting here implements
  // the contract rather than guessing.
  const operator = clause.operator ?? 'eq'
  const mode = clause.mode ?? 'sensitive'
  const field = mapField === undefined ? baFieldToPayload(clause.field) : mapField(clause.field)
  if (clause.value === null) {
    if (operator === 'eq') {
      return { where: { [field]: { exists: false } } }
    }
    if (operator === 'ne') {
      return { where: { [field]: { exists: true } } }
    }
    throw new UnsupportedOperatorError(`${operator} with null`)
  }
  const value = toPayloadValue(clause.value, coerceValue, clause.field)
  switch (operator) {
    case 'eq': {
      if (mode === 'insensitive' && typeof clause.value === 'string') {
        const wanted = clause.value.toLowerCase()
        return {
          // `like` narrows case-insensitively; the post-filter exacts the
          // match so a contains-query never returns the wrong row.
          where: { [field]: { like: clause.value } },
          postFilter: (row) => {
            const actual = row[clause.field]
            return typeof actual === 'string' && actual.toLowerCase() === wanted
          },
        }
      }
      if (mode === 'insensitive') {
        throw new UnsupportedOperatorError('eq insensitive on non-string')
      }
      return { where: { [field]: { equals: value } } }
    }
    case 'ne':
      if (mode === 'insensitive') {
        throw new UnsupportedOperatorError('ne insensitive')
      }
      return { where: { [field]: { not_equals: value } } }
    case 'lt':
      return { where: { [field]: { less_than: value } } }
    case 'lte':
      return { where: { [field]: { less_than_equal: value } } }
    case 'gt':
      return { where: { [field]: { greater_than: value } } }
    case 'gte':
      return { where: { [field]: { greater_than_equal: value } } }
    case 'in':
    case 'not_in':
      if (mode === 'insensitive') {
        throw new UnsupportedOperatorError(`${operator} insensitive`)
      }
      return { where: { [field]: { [operator]: value } } }
    case 'contains':
    case 'starts_with':
    case 'ends_with':
      // No exact Payload equivalent; failing loud beats a silently
      // wrong translation.
      throw new UnsupportedOperatorError(operator)
    default:
      // A newly added Better Auth operator must fail typecheck here
      // (B17), never reach a request as a generic runtime throw.
      return assertNever(operator)
  }
}

/**
 * Translate a Better Auth `where` list to Payload `Where`, folding mixed
 * `AND`/`OR` connectors left-associatively. Pattern operators and
 * case-insensitive non-equality have no faithful translation and throw
 * {@link UnsupportedOperatorError}.
 *
 * The returned `postFilter` runs over Better Auth-shaped rows (with `id`,
 * not `baId`) and exacts case-insensitive equality; it is `undefined`
 * when the Payload query alone is exact.
 */
export function translateWhereClause(
  clauses: readonly CleanedWhere[],
  mapField?: FieldResolver,
  coerceValue?: (field: string, value: unknown) => unknown
): {
  where: Where
  postFilter: ((row: Record<string, unknown>) => boolean) | undefined
} {
  const postFilters: ((row: Record<string, unknown>) => boolean)[] = []
  const conditions = clauses.map((clause) => {
    const translated = clauseToWhere(clause, mapField, coerceValue)
    if (translated.postFilter) {
      postFilters.push(translated.postFilter)
    }
    return { condition: translated.where, connector: clause.connector ?? 'AND' }
  })
  let where: Where = {}
  for (const [index, entry] of conditions.entries()) {
    if (index === 0) {
      where = entry.condition
      continue
    }
    where =
      entry.connector === 'OR'
        ? { or: [where, entry.condition] }
        : { and: [where, entry.condition] }
  }
  return {
    where,
    postFilter:
      postFilters.length === 0
        ? undefined
        : (row) => postFilters.every((postFilter) => postFilter(row)),
  }
}
