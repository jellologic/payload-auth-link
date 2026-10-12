/**
 * Runtime narrowing guards for untrusted SDK and storage shapes. One
 * definition shared by every package — adapters narrow through these,
 * never through local copies.
 */

/** Plain-object check for narrowing `unknown` payloads. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

/** Non-empty-string check for required string fields. */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== ''
}

/**
 * Coerce `Date`s, ISO strings, and epoch numbers to a valid `Date`.
 * Anything else (including `NaN` dates) yields `null` — fail closed.
 */
export function toDate(value: unknown): Date | null {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime()) ? null : parsed
  }
  return null
}
