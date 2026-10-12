import { err, ok, type Result } from 'neverthrow'
import { z } from 'zod'
import { InvalidEmailError } from './errors.js'

/**
 * Email boundary schema: valid format, max 320 chars, lowercased,
 * branded so only {@link parseEmail} output inhabits `Email`.
 */
export const emailSchema = z.email('must be a valid email').max(320).toLowerCase().brand<'Email'>()

/**
 * A validated, lowercased email address.
 * Construct only via {@link parseEmail}.
 */
export type Email = z.output<typeof emailSchema>

/** Smart constructor: the one place raw input becomes an `Email`. */
export function parseEmail(value: unknown): Result<Email, InvalidEmailError> {
  const parsed = emailSchema.safeParse(value)
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => issue.message).join('; ')
    return err(new InvalidEmailError(detail))
  }
  return ok(parsed.data)
}
