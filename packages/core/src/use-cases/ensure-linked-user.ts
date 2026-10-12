import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import { RepositoryError, UnverifiedEmailError, UserExistsError } from '../errors.js'
import type {
  LoggerPort,
  NewUser,
  ProviderId,
  ProviderIdentityRef,
  ProviderProfile,
  UserRecord,
  UserRepository,
} from '../ports.js'
import type { Role } from '../roles.js'

export type EnsureLinkedUserDeps = {
  readonly users: UserRepository
  readonly logger: LoggerPort
}

export type EnsureLinkedUserInput = {
  readonly providerId: ProviderId
  readonly profile: ProviderProfile
  /** Roles for a newly created user. Existing users keep their roles. */
  readonly defaultRoles: readonly Role[]
}

/**
 * Bridge a provider identity to a Payload user, converging link and email.
 * Idempotent: an already-linked identity returns its user, syncing the
 * email when the provider reports a new verified address (an unverified
 * change is logged and kept stale, never applied); a matching email
 * links only when the provider verified it, otherwise the link is refused
 * with {@link UnverifiedEmailError} (no unverified-email account
 * takeover); an unknown email creates a fresh user with `defaultRoles`.
 *
 * `UserExistsError` escapes only on a lost create race: two concurrent
 * first touches for the same email. Callers retry the read once, which
 * then finds the winner's link.
 *
 * Verification gates creation exactly like linking: an unverified
 * provider email for an unknown address refuses with
 * {@link UnverifiedEmailError} instead of provisioning a full user,
 * so OAuth (or any flow yielding unverified sessions) cannot mint
 * default-role accounts.
 */
export function ensureLinkedUser(
  deps: EnsureLinkedUserDeps,
  input: EnsureLinkedUserInput
): ResultAsync<UserRecord, RepositoryError | UnverifiedEmailError | UserExistsError> {
  const ref: ProviderIdentityRef = {
    providerId: input.providerId,
    providerUserId: input.profile.providerUserId,
  }
  return deps.users.findByProviderIdentity(ref).andThen((linked) => {
    if (linked) {
      if (linked.email === input.profile.email) {
        return okAsync(linked)
      }
      if (!input.profile.emailVerified) {
        deps.logger.warn('email sync skipped: provider address unverified', {
          userId: linked.id,
          providerId: input.providerId,
        })
        return okAsync(linked)
      }
      return deps.users.setEmail(linked.id, input.profile.email).map((user) => {
        deps.logger.info('email synced from provider', {
          userId: user.id,
          providerId: input.providerId,
        })
        return user
      })
    }
    return deps.users.findByEmail(input.profile.email).andThen((existing) => {
      if (existing) {
        if (!input.profile.emailVerified) {
          deps.logger.warn('link refused: provider email unverified', {
            email: input.profile.email,
            providerId: input.providerId,
          })
          return errAsync(new UnverifiedEmailError(input.profile.email))
        }
        return deps.users.linkIdentity(existing.id, ref).map((user) => {
          deps.logger.info('identity linked', {
            userId: user.id,
            providerId: input.providerId,
          })
          return user
        })
      }
      if (!input.profile.emailVerified) {
        deps.logger.warn('registration refused: provider email unverified', {
          email: input.profile.email,
          providerId: input.providerId,
        })
        return errAsync(new UnverifiedEmailError(input.profile.email))
      }
      const candidate: NewUser = {
        email: input.profile.email,
        roles: input.defaultRoles,
        identity: ref,
      }
      return deps.users.create(candidate).map((user) => {
        deps.logger.info('user registered via provider', {
          userId: user.id,
          providerId: input.providerId,
        })
        return user
      })
    })
  })
}
