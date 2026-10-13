import { okAsync, type ResultAsync } from 'neverthrow'
import { assertNever } from '../assert.js'
import type { RepositoryError, UserExistsError } from '../errors.js'
import type { IdentityEvent } from '../events.js'
import type { LoggerPort, UserRepository } from '../ports.js'

/**
 * Apply one provider {@link IdentityEvent} to the Payload user store
 * (CAP-14). Payload stays the single user store (invariant 1, D9):
 *
 * - `email-changed` syncs via `setEmail` only when the provider
 *   verified the new address; an unverified change is ignored.
 * - `email-verified` syncs the address when it differs.
 * - `identity-unlinked` and `user-deleted` remove only the identity
 *   row; the Payload user always remains.
 * - An event for a provider user with no linked Payload user is a
 *   no-op: that user was never linked (or was already unlinked).
 *
 * Never creates or deletes a Payload user.
 */
export function applyIdentityEvent(
  users: UserRepository,
  event: IdentityEvent,
  logger: LoggerPort
): ResultAsync<void, RepositoryError | UserExistsError> {
  const ref = { providerId: event.providerId, providerUserId: event.providerUserId }
  if (event.type === 'email-changed' && !event.verified) {
    logger.warn('identity event ignored: unverified email change (D9)', {
      providerId: event.providerId,
      providerUserId: event.providerUserId,
    })
    return okAsync(undefined)
  }
  return users.findByProviderIdentity(ref).andThen((user) => {
    if (user === null) {
      logger.info('identity event for unlinked provider user: no-op', {
        type: event.type,
        providerId: event.providerId,
        providerUserId: event.providerUserId,
      })
      return okAsync(undefined)
    }
    switch (event.type) {
      case 'email-changed':
      case 'email-verified':
        // setEmail is already an idempotent no-op when unchanged.
        return users.setEmail(user.id, event.email).map(() => undefined)
      case 'identity-unlinked':
      case 'user-deleted':
        return users.unlinkIdentity(user.id, ref).map(() => undefined)
    }
    // A new IdentityEvent variant must fail typecheck here (B17),
    // never fall through as a silent no-op at runtime.
    return assertNever(event)
  })
}
