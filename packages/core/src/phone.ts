import { err, ok, type Result } from 'neverthrow'
import { z } from 'zod'
import { InvalidPhoneNumberError } from './errors.js'

/**
 * Phone-number boundary schema: E.164 only (`+` then a country-code-led
 * run of 7–15 digits), branded so only {@link parsePhoneNumber} output
 * inhabits `PhoneNumber`.
 *
 * Minimal by design (PORT-1): core needs the branded type so session
 * identity claims can carry a phone. Display/national formatting and
 * the verified-phone linking policy are CAP-9 (Phase 6), not here.
 */
export const phoneNumberSchema = z
  .string()
  .regex(/^\+[1-9]\d{6,14}$/, 'must be an E.164 phone number (e.g. +14155550132)')
  .brand<'PhoneNumber'>()

/**
 * A validated E.164 phone number.
 * Construct only via {@link parsePhoneNumber}.
 */
export type PhoneNumber = z.output<typeof phoneNumberSchema>

/** Smart constructor: the one place raw input becomes a `PhoneNumber`. */
export function parsePhoneNumber(value: unknown): Result<PhoneNumber, InvalidPhoneNumberError> {
  const parsed = phoneNumberSchema.safeParse(value)
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => issue.message).join('; ')
    return err(new InvalidPhoneNumberError(detail))
  }
  return ok(parsed.data)
}
