import { err, errAsync, ok, okAsync, ResultAsync } from 'neverthrow'
import {
  defineSessionId,
  ensureLinkedUser,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnverifiedEmailError,
  UserExistsError,
  type ClockPort,
  type LoggerPort,
  type ProviderError,
  type ProviderId,
  type ProviderProfile,
  type ProviderRegistry,
  type ProviderSession,
  type Role,
  type Session,
  type SessionPort,
  type UnknownProviderError,
  type UserRecord,
  type UserRepository,
} from '@payload-auth-link/core'

/** `SessionPort` wiring: user store, provider registry, leaf ports. */
export type SessionServiceDeps = {
  readonly users: UserRepository
  readonly registry: ProviderRegistry
  readonly logger: LoggerPort
  readonly clock: ClockPort
  /** Roles for users provisioned just-in-time at first verification. */
  readonly defaultRoles: readonly Role[]
}

type FoundProviderSession = {
  readonly providerId: ProviderId
  readonly providerSession: ProviderSession
}

/**
 * Ask each registered provider for a session. Provider failures are logged
 * and skipped (one provider being down must not break the others); a total
 * absence of sessions yields `null`, never an exception.
 *
 * Precedence is registry order: the first registered provider presenting a
 * live session wins, and later providers are not consulted. Logout sweeps
 * every provider regardless (see `endpoints.ts`).
 */
async function findProviderSession(
  deps: SessionServiceDeps,
  headers: Headers
): Promise<FoundProviderSession | null> {
  for (const id of deps.registry.ids()) {
    const required = deps.registry.require(id)
    if (required.isErr()) {
      continue
    }
    const provider = required.value
    const current = await provider.getSession(headers)
    if (current.isErr()) {
      deps.logger.warn('provider session read failed', { providerId: provider.id })
      continue
    }
    if (current.value) {
      return { providerId: provider.id, providerSession: current.value }
    }
  }
  return null
}

/**
 * `SessionPort` bridging provider sessions to Payload users. Provider state
 * is never touched (no refresh, no writes); Payload users are provisioned
 * just-in-time and idempotently at verification, so no signup ordering can
 * strand a provider user without its Payload document.
 */
export function createSessionService(deps: SessionServiceDeps): SessionPort {
  return {
    verify(
      headers: Headers
    ): ResultAsync<Session, SessionInvalidError | SessionExpiredError | RepositoryError> {
      return ResultAsync.fromPromise<FoundProviderSession | null, SessionInvalidError>(
        findProviderSession(deps, headers),
        (cause) => new SessionInvalidError(`verification failed: ${String(cause)}`)
      ).andThen((found) => {
        if (!found) {
          return err(new SessionInvalidError('no active provider session'))
        }
        // Port contract violation (empty id): a 401, never a thrown 500
        // from `defineSessionId` below.
        if (found.providerSession.sessionId === '') {
          deps.logger.warn('provider returned an empty session id', {
            providerId: found.providerId,
          })
          return err(new SessionInvalidError('provider session has no id'))
        }
        // No clock-skew leeway, by design: a leeway would accept sessions
        // the provider already considers expired. The plugin host and the
        // provider's session store must keep synchronized clocks (NTP) —
        // a documented hard requirement (docs/concepts.md).
        if (found.providerSession.expiresAt.getTime() <= deps.clock.now().getTime()) {
          return err(new SessionExpiredError())
        }
        const ref = {
          providerId: found.providerId,
          providerUserId: found.providerSession.providerUserId,
        }
        const profile: ProviderProfile = {
          providerUserId: found.providerSession.providerUserId,
          email: found.providerSession.email,
          emailVerified: found.providerSession.emailVerified,
          name: null,
          image: null,
        }
        const toSession = (user: UserRecord): Session => ({
          id: defineSessionId(found.providerSession.sessionId),
          userId: user.id,
          providerId: found.providerId,
          expiresAt: found.providerSession.expiresAt,
        })
        // Single-read resolution: `ensureLinkedUser` opens with the same
        // identity lookup (returning immediately on a linked match), so a
        // pre-read here would only double the miss path. The lost-create-race
        // retry below is the only second read, and only on that race.
        return ensureLinkedUser(
          { users: deps.users, logger: deps.logger },
          {
            providerId: found.providerId,
            profile,
            defaultRoles: deps.defaultRoles,
          }
        )
          .orElse(
            (
              error
            ): ResultAsync<
              UserRecord,
              RepositoryError | UnverifiedEmailError | UserExistsError | SessionInvalidError
            > => {
              if (!(error instanceof UserExistsError)) {
                return errAsync(error)
              }
              // Lost a create race: the winner's link is readable now.
              deps.logger.info('user provision raced; retrying read', {
                providerId: found.providerId,
              })
              return deps.users.findByProviderIdentity(ref).andThen((user) => {
                if (!user) {
                  return errAsync(new SessionInvalidError('session has no linked user'))
                }
                return okAsync(user)
              })
            }
          )
          .andThen((user) => ok(toSession(user)))
          .mapErr((error): SessionInvalidError | SessionExpiredError | RepositoryError => {
            // Repository outages stay typed (with their cause) so callers
            // can log them as errors; unverified identities are invalid
            // sessions for linking purposes.
            if (error instanceof SessionInvalidError || error instanceof RepositoryError) {
              return error
            }
            return new SessionInvalidError(error.message)
          })
      })
    },

    revoke(session: Session): ResultAsync<void, UnknownProviderError | ProviderError> {
      const required = deps.registry.require(session.providerId)
      if (required.isErr()) {
        return errAsync(required.error)
      }
      return required.value.revokeSession(session.id)
    },
  }
}
