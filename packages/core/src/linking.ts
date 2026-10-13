import { err, ok, type Result } from 'neverthrow'
import { z } from 'zod'
import { InvalidConfigError } from './errors.js'

/**
 * Declared policy for linking a provider identity to a Payload user
 * (PORT-3). The policy names which verified identifier claims may act
 * as the linking authority in `ensureLinkedUser`:
 *
 * - `'verified-email'` (the default): only a provider-verified email
 *   claim links to an existing user or provisions a new one. This is
 *   the pre-PORT-3 hard-coded rule, unchanged.
 * - `'verified-email-or-phone'`: the email rule above, plus one
 *   additional branch for phone-only identities (no email claim): a
 *   provider-verified E.164 phone claim links to the _existing_ user
 *   resolved through `UserRepository.findByPhone`. The branch never
 *   provisions a user — an unmatched verified phone refuses with
 *   `UnverifiedIdentityError`.
 *
 * Anonymous identities (`identity.anonymous === true`) never link
 * under any policy (D3).
 */
/**
 * Linking-policy boundary schema. Strict and discriminated on `kind`:
 * unknown kinds and unknown keys are rejected, never silently mapped
 * to the default. Defined before {@link LinkingPolicy} so the domain
 * type derives from the schema (single source, B16): the hand-written
 * `readonly` union it replaced was assignable but not identical to
 * the schema output — exactly the drift the type-alarms pin catches.
 */
export const linkingPolicySchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('verified-email') }).strict(),
  z.object({ kind: z.literal('verified-email-or-phone') }).strict(),
])

export type LinkingPolicy = Readonly<z.output<typeof linkingPolicySchema>>

/**
 * The default linking policy: verified email only. Used by
 * `ensureLinkedUser` when `EnsureLinkedUserInput.linkingPolicy` is
 * omitted, so existing callers keep byte-identical behavior.
 */
export const defaultLinkingPolicy: LinkingPolicy = { kind: 'verified-email' }

/**
 * Parse an untyped linking policy (for example from plugin options).
 * Returns {@link InvalidConfigError} on any shape the strict schema
 * rejects — wiring fails fast instead of degrading to the default.
 */
export function parseLinkingPolicy(value: unknown): Result<LinkingPolicy, InvalidConfigError> {
  const parsed = linkingPolicySchema.safeParse(value)
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => issue.message).join('; ')
    return err(new InvalidConfigError(`linkingPolicy: ${detail}`))
  }
  return ok(parsed.data)
}
