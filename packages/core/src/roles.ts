import { err, ok, type Result } from 'neverthrow'
import { z } from 'zod'
import { InvalidRoleError } from './errors.js'

/** Role boundary schema: lowercase slug, branded `Role`. */
export const roleSchema = z
  .string()
  .min(1, 'role must not be empty')
  .max(64, 'role must be at most 64 characters')
  .regex(/^[a-z0-9][a-z0-9_-]*$/, 'role must be lowercase alphanumeric with - or _')
  .brand<'Role'>()

/** A canonical role. Construct only via {@link parseRole}. */
export type Role = z.output<typeof roleSchema>

/** Smart constructor: the one place raw input becomes a `Role`. */
export function parseRole(value: unknown): Result<Role, InvalidRoleError> {
  const parsed = roleSchema.safeParse(value)
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => issue.message).join('; ')
    return err(new InvalidRoleError(detail))
  }
  return ok(parsed.data)
}
