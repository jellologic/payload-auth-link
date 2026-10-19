import { errAsync, okAsync, type ResultAsync } from 'neverthrow'
import { assertNever } from '../assert.js'
import {
  RepositoryError,
  UnverifiedEmailError,
  UnverifiedIdentityError,
  UserExistsError,
} from '../errors.js'
import { defaultLinkingPolicy, type LinkingPolicy } from '../linking.js'
import type { PhoneNumber } from '../phone.js'
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
  /**
   * Which verified claims may link (PORT-3). Defaults to
   * {@link defaultLinkingPolicy} (`verified-email`), preserving the
   * pre-PORT-3 behavior for callers that omit it.
   */
  readonly linkingPolicy?: LinkingPolicy | undefined
}

type EnsureLinkedUserError =
  RepositoryError | UnverifiedEmailError | UnverifiedIdentityError | UserExistsError

/**
 * The opt-in verified-phone branch (PORT-3): link a phone-only
 * identity to an _existing_ user resolved by `findByPhone`. Never
 * provisions — every refusal here is {@link UnverifiedIdentityError}:
 * no verified phone claim, no repository phone support, or no
 * existing user holding that number.
 */
function linkByVerifiedPhone(
  deps: EnsureLinkedUserDeps,
  input: EnsureLinkedUserInput,
  ref: ProviderIdentityRef,
  phone: PhoneNumber
): ResultAsync<UserRecord, EnsureLinkedUserError> {
  const { findByPhone } = deps.users
  if (findByPhone === undefined) {
    deps.logger.warn('phone link refused: repository does not support findByPhone', {
      providerId: input.providerId,
    })
    return errAsync(
      new UnverifiedIdentityError('user repository does not support phone lookup (findByPhone)')
    )
  }
  return findByPhone.call(deps.users, phone).andThen((existing) => {
    if (!existing) {
      deps.logger.warn('phone link refused: no existing user holds the verified phone', {
        providerId: input.providerId,
      })
      return errAsync(
        new UnverifiedIdentityError(
          'verified phone does not match an existing user; phone linking never provisions a user'
        )
      )
    }
    return deps.users.linkIdentity(existing.id, ref).map((user) => {
      deps.logger.info('identity linked by verified phone', {
        userId: user.id,
        providerId: input.providerId,
      })
      return user
    })
  })
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
 * Before the email path, a repository exposing
 * `findByProviderOwnedId` (adopt mode: the provider's user ids ARE the
 * document ids, issue #124) resolves the engine's own row by id and
 * links it without an email proof — the row could only have been
 * created by the engine. The email sync of the already-linked branch
 * is not repeated here: with the identity row written, the next
 * request takes that branch and converges the email as usual.
 *
 * The linking authority is the declared {@link LinkingPolicy}
 * (PORT-3) over the `identity` claims (PORT-1): the deprecated
 * `email`/`emailVerified` aliases on the profile are never read here.
 * Under the default policy a missing email claim refuses with
 * {@link UnverifiedIdentityError} and an unverified claim refuses
 * exactly as the flat flag did before — byte-identical to the
 * pre-claim gate (V1), which the existing tests pin as the regression
 * spec. The opt-in `verified-email-or-phone` policy adds exactly one
 * branch: a phone-only identity (no email claim) carrying a verified
 * phone claim links to an existing user by phone and never
 * provisions. An anonymous identity never links under any policy
 * (D3), not even to an already-linked user.
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
): ResultAsync<
  UserRecord,
  RepositoryError | UnverifiedEmailError | UnverifiedIdentityError | UserExistsError
> {
  const ref: ProviderIdentityRef = {
    providerId: input.providerId,
    providerUserId: input.profile.providerUserId,
  }
  const policy = input.linkingPolicy ?? defaultLinkingPolicy
  // D3: anonymous identities never link, under any policy — checked
  // before the already-linked fast path so an anonymous session can
  // never ride a previously linked identity.
  if (input.profile.identity.anonymous) {
    deps.logger.warn('link refused: anonymous identity never links', {
      providerId: input.providerId,
    })
    return errAsync(new UnverifiedIdentityError('anonymous identities never link to a user'))
  }
  const emailClaim = input.profile.identity.email
  const phoneClaim = input.profile.identity.phone
  const verifiedPhone = phoneClaim !== null && phoneClaim.verified ? phoneClaim.value : undefined
  // CAP-9 phone sync: a verified phone claim is stored on the linked
  // user (when the repository supports it and the value differs) so a
  // later phone-only sign-in can resolve by `findByPhone`. Sync
  // failures are logged and never fail an otherwise valid link — the
  // phone is an additional identifier, not the linking authority here.
  const syncPhone = (user: UserRecord): ResultAsync<UserRecord, EnsureLinkedUserError> => {
    if (verifiedPhone === undefined || user.phone === verifiedPhone) {
      return okAsync(user)
    }
    const { setPhone } = deps.users
    if (setPhone === undefined) {
      return okAsync(user)
    }
    return setPhone
      .call(deps.users, user.id, verifiedPhone)
      .map((updated) => {
        deps.logger.info('phone synced from provider', {
          userId: updated.id,
          providerId: input.providerId,
        })
        return updated
      })
      .orElse((error) => {
        deps.logger.warn('phone sync failed; keeping linked user', {
          userId: user.id,
          providerId: input.providerId,
          cause: error,
        })
        return okAsync(user)
      })
  }
  return deps.users.findByProviderIdentity(ref).andThen((linked) => {
    if (linked) {
      // A phone-only identity has no email to sync; the existing link
      // is the whole answer.
      if (emailClaim === null) {
        return okAsync(linked)
      }
      const claimEmail = emailClaim.value
      const claimVerified = emailClaim.verified
      if (linked.email === claimEmail) {
        return syncPhone(linked)
      }
      if (!claimVerified) {
        deps.logger.warn('email sync skipped: provider address unverified', {
          userId: linked.id,
          providerId: input.providerId,
        })
        return okAsync(linked)
      }
      return deps.users
        .setEmail(linked.id, claimEmail)
        .map((user) => {
          deps.logger.info('email synced from provider', {
            userId: user.id,
            providerId: input.providerId,
          })
          return user
        })
        .andThen(syncPhone)
    }
    if (emailClaim === null) {
      // Phone-only identity: the declared policy decides. The default
      // refuses exactly as the pre-PORT-3 gate did; the opt-in branch
      // links by verified phone to an existing user only.
      switch (policy.kind) {
        case 'verified-email': {
          deps.logger.warn('link refused: session carries no email identity claim', {
            providerId: input.providerId,
          })
          return errAsync(
            new UnverifiedIdentityError('provider session carries no email identity claim')
          )
        }
        case 'verified-email-or-phone': {
          const phoneClaim = input.profile.identity.phone
          if (phoneClaim === null || !phoneClaim.verified) {
            deps.logger.warn('phone link refused: no verified phone identity claim', {
              providerId: input.providerId,
            })
            return errAsync(
              new UnverifiedIdentityError(
                'provider session carries no verified phone identity claim'
              )
            )
          }
          return linkByVerifiedPhone(deps, input, ref, phoneClaim.value)
        }
        default:
          return assertNever(policy)
      }
    }
    // The email path, extracted so the adopt-mode id link can fall
    // through to it.
    const linkByEmailOrProvision = (): ResultAsync<UserRecord, EnsureLinkedUserError> => {
      const claimEmail = emailClaim.value
      const claimVerified = emailClaim.verified
      return deps.users.findByEmail(claimEmail).andThen((existing) => {
        if (existing) {
          if (!claimVerified) {
            deps.logger.warn('link refused: provider email unverified', {
              email: claimEmail,
              providerId: input.providerId,
            })
            return errAsync(new UnverifiedEmailError(claimEmail))
          }
          return deps.users
            .linkIdentity(existing.id, ref)
            .map((user) => {
              deps.logger.info('identity linked', {
                userId: user.id,
                providerId: input.providerId,
              })
              return user
            })
            .andThen(syncPhone)
        }
        if (!claimVerified) {
          // CAP-9: under the opt-in policy, a session whose email is an
          // unverified placeholder (e.g. a BA phone sign-up's temp
          // address, held by no existing user — checked above) may
          // still link by a VERIFIED phone claim. The unverified email
          // itself never links or provisions.
          if (policy.kind === 'verified-email-or-phone' && verifiedPhone !== undefined) {
            return linkByVerifiedPhone(deps, input, ref, verifiedPhone)
          }
          deps.logger.warn('registration refused: provider email unverified', {
            email: claimEmail,
            providerId: input.providerId,
          })
          return errAsync(new UnverifiedEmailError(claimEmail))
        }
        const candidate: NewUser = {
          email: claimEmail,
          roles: input.defaultRoles,
          identity: ref,
          ...(verifiedPhone === undefined ? {} : { phone: verifiedPhone }),
        }
        return deps.users.create(candidate).map((user) => {
          deps.logger.info('user registered via provider', {
            userId: user.id,
            providerId: input.providerId,
          })
          return user
        })
      })
    }
    // Adopt mode (issue #124): the engine wrote the user's row itself,
    // under the provider user id AS the document id, so the row exists
    // before any identity row does. Link it first — no email proof is
    // needed, because nobody but the engine can mint a document with
    // that id (see the port fact). Running before the email path keeps
    // a fresh sign-up away from the email-collision refusal its own
    // unproven row would otherwise trip, and writes the same identity
    // row `adopt-prelink` writes for pre-cutover users.
    const findByProviderOwnedId = deps.users.findByProviderOwnedId
    if (findByProviderOwnedId === undefined) {
      return linkByEmailOrProvision()
    }
    return findByProviderOwnedId.call(deps.users, ref).andThen((owned) => {
      if (!owned) {
        return linkByEmailOrProvision()
      }
      return deps.users
        .linkIdentity(owned.id, ref)
        .map((user) => {
          deps.logger.info('identity linked by provider-owned document id', {
            userId: user.id,
            providerId: input.providerId,
          })
          return user
        })
        .andThen(syncPhone)
    })
  })
}
