import { err, errAsync, okAsync, ResultAsync } from 'neverthrow'
import {
  ChannelNotAdmittedError,
  defineSessionId,
  ensureLinkedUser,
  isSuspendedAt,
  RepositoryError,
  SessionExpiredError,
  SessionInvalidError,
  UnverifiedEmailError,
  UnverifiedIdentityError,
  UserExistsError,
  UserSuspendedError,
  type ClockPort,
  type Email,
  type GuestPrincipal,
  type LinkingPolicy,
  type LoggerPort,
  type ProviderError,
  type ProviderId,
  type ProviderProfile,
  type ProviderRegistry,
  type ProviderSession,
  type ResolvedSessionActor,
  type Role,
  type Session,
  type SessionChannel,
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
  /**
   * Linking policy passed to `ensureLinkedUser` (PORT-3). Optional:
   * omitted means core's default (`verified-email`).
   */
  readonly linkingPolicy?: LinkingPolicy | undefined
  /**
   * Session channels verification admits (CAP-13a). Optional: omitted
   * means `['cookie']`, matching the plugin option default. A live
   * session on any other channel is refused with
   * {@link ChannelNotAdmittedError} before any linking happens.
   */
  readonly admitChannels?: readonly SessionChannel[] | undefined
  /**
   * Enterprise SSO domain guard (CAP-15): when wired, a session from
   * an SSO-registered provider links only if this returns `true` for
   * its asserted email (the composition root checks the email domain
   * against Payload organizations' verified domains, and returns
   * `true` untouched for non-SSO providers). A `false` refuses
   * verification before any linking — a tenant IdP asserting a
   * foreign domain can never reach `ensureLinkedUser`.
   */
  readonly ssoDomainAllowed?:
    | ((providerId: ProviderId, email: Email | null) => ResultAsync<boolean, RepositoryError>)
    | undefined
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
  const admitChannels: readonly SessionChannel[] = deps.admitChannels ?? ['cookie']
  return {
    verify(
      headers: Headers
    ): ResultAsync<
      Session,
      | SessionInvalidError
      | SessionExpiredError
      | ChannelNotAdmittedError
      | UserSuspendedError
      | RepositoryError
    > {
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
        // Channel gate (CAP-13a): a live session presented on a
        // channel the host does not admit is refused before any
        // linking or JIT provisioning — a valid bearer credential
        // must not mint a Payload user through a cookie-only policy.
        // Verification stops at the presenting provider (registry
        // precedence), so a denied channel never falls through.
        if (!admitChannels.includes(found.providerSession.channel)) {
          deps.logger.warn('provider session channel not admitted', {
            providerId: found.providerId,
            channel: found.providerSession.channel,
          })
          return err(new ChannelNotAdmittedError(found.providerSession.channel, admitChannels))
        }
        const ref = {
          providerId: found.providerId,
          providerUserId: found.providerSession.providerUserId,
        }
        // `ensureLinkedUser` owns the linking decision (PORT-3): no
        // null-email pre-rejection here, so its already-linked fast
        // path and the opt-in verified-phone branch stay reachable
        // for email-less sessions. Refusals still arrive typed
        // (`UnverifiedIdentityError` etc.) and map to 401 below; the
        // anonymous gate (D3) also lives in the use-case, before the
        // fast path, so an anonymous session is refused even when
        // previously linked. The deprecated profile aliases fall back
        // to the session's alias fields when there is no email claim
        // — the use-case never reads them.
        const emailClaim = found.providerSession.identity.email
        const profile: ProviderProfile = {
          providerUserId: found.providerSession.providerUserId,
          identity: found.providerSession.identity,
          email: emailClaim?.value ?? found.providerSession.email,
          emailVerified: emailClaim?.verified ?? found.providerSession.emailVerified,
          name: null,
          image: null,
        }
        // PORT-4 projection: carry the provider's session facts onto
        // the plugin session. `assurance` is always reported by the
        // port (PORT-1), so it is always carried — including its
        // `'unknown'` values, which consumers treat as unsatisfied.
        // `actor`/`organizationId` appear only when known (a live
        // impersonation / an active tenant), never as `null`.
        const { assurance, actor, organizationId } = found.providerSession
        const toSession = (
          user: UserRecord,
          resolvedActor: ResolvedSessionActor | null
        ): Session => ({
          id: defineSessionId(found.providerSession.sessionId),
          userId: user.id,
          providerId: found.providerId,
          expiresAt: found.providerSession.expiresAt,
          assurance: {
            methods: assurance.methods === 'unknown' ? 'unknown' : [...assurance.methods],
            mfa: assurance.mfa,
          },
          ...(resolvedActor === null ? {} : { actor: resolvedActor }),
          ...(organizationId === null ? {} : { organizationId }),
        })
        // Single-read resolution: `ensureLinkedUser` opens with the same
        // identity lookup (returning immediately on a linked match), so a
        // pre-read here would only double the miss path. The lost-create-race
        // retry below is the only second read, and only on that race.
        const linkUser = () =>
          ensureLinkedUser(
            { users: deps.users, logger: deps.logger },
            {
              providerId: found.providerId,
              profile,
              defaultRoles: deps.defaultRoles,
              ...(deps.linkingPolicy === undefined ? {} : { linkingPolicy: deps.linkingPolicy }),
            }
          )
        // SSO domain gate (CAP-15): runs before any linking when
        // wired; the checker itself decides applicability per provider.
        const linkedUser =
          deps.ssoDomainAllowed === undefined
            ? linkUser()
            : deps
                .ssoDomainAllowed(found.providerId, emailClaim?.value ?? null)
                .andThen((allowed) => {
                  if (!allowed) {
                    deps.logger.warn(
                      'sso session refused: email domain not verified for any organization',
                      {
                        providerId: found.providerId,
                      }
                    )
                    return errAsync(
                      new UnverifiedIdentityError(
                        'sso email domain is not a verified organization domain'
                      )
                    )
                  }
                  return linkUser()
                })
        return linkedUser
          .orElse(
            (
              error
            ): ResultAsync<
              UserRecord,
              | RepositoryError
              | UnverifiedEmailError
              | UnverifiedIdentityError
              | UserExistsError
              | SessionInvalidError
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
          .andThen((user) => {
            // Suspension gate (CAP-7): Payload owns the suspension and
            // the user was just reloaded, so this refuses every
            // provider and every strategy — including stateless JWTs
            // no provider-side revoke can reach. Runs before actor
            // resolution: a suspended target must not verify even
            // under impersonation.
            if (isSuspendedAt(user.suspendedUntil, deps.clock.now())) {
              deps.logger.warn('session refused: user suspended', {
                providerId: found.providerId,
                userId: String(user.id),
                suspendedUntil: user.suspendedUntil?.toISOString(),
              })
              return errAsync(new UserSuspendedError(user.suspendedUntil ?? deps.clock.now()))
            }
            return okAsync(user)
          })
          .andThen((user) => {
            // Actor resolution (CAP-8b): resolve the impersonating
            // operator to their Payload user via the identity link,
            // so `Session.actor` names a Payload user when one
            // exists. An operator with no linked Payload user stays
            // in the distinct `provider-only` form (fail-closed: the
            // actor is never dropped and never dressed up as a
            // Payload id, impersonation access policy still applies,
            // and the unresolved state is audit-logged). A repository
            // failure propagates as `RepositoryError` — verification
            // refuses rather than losing the actor silently.
            if (actor === null) {
              return okAsync(toSession(user, null))
            }
            return deps.users
              .findByProviderIdentity({
                providerId: found.providerId,
                providerUserId: actor.providerUserId,
              })
              .map((actorUser) => {
                const resolvedActor: ResolvedSessionActor =
                  actorUser === null
                    ? { kind: 'provider-only', providerUserId: actor.providerUserId }
                    : {
                        kind: 'payload-user',
                        providerUserId: actor.providerUserId,
                        userId: actorUser.id,
                      }
                // Impersonation audit (CAP-8a): every verified use
                // of an impersonated session is logged with the
                // operator and target ids (never the session token
                // or email), so actions taken as the target are
                // attributable. Per-operation auditing of Payload
                // operations rides the same actor (see `audit.ts`).
                deps.logger.info('impersonated session used', {
                  providerId: found.providerId,
                  actorProviderUserId: actor.providerUserId,
                  actorKind: resolvedActor.kind,
                  ...(resolvedActor.kind === 'payload-user'
                    ? { actorUserId: String(resolvedActor.userId) }
                    : {}),
                  targetProviderUserId: found.providerSession.providerUserId,
                  targetUserId: String(user.id),
                })
                if (resolvedActor.kind === 'provider-only') {
                  deps.logger.warn('impersonated session actor has no linked Payload user', {
                    providerId: found.providerId,
                    actorProviderUserId: actor.providerUserId,
                    targetUserId: String(user.id),
                  })
                }
                return toSession(user, resolvedActor)
              })
          })
          .mapErr(
            (
              error
            ): SessionInvalidError | SessionExpiredError | UserSuspendedError | RepositoryError => {
              // Repository outages and suspensions stay typed so
              // callers can log/present them distinctly; unverified
              // identities are invalid sessions for linking purposes.
              if (
                error instanceof SessionInvalidError ||
                error instanceof RepositoryError ||
                error instanceof UserSuspendedError
              ) {
                return error
              }
              return new SessionInvalidError(error.message)
            }
          )
      })
    },

    guest(headers: Headers): ResultAsync<GuestPrincipal | null, RepositoryError> {
      // CAP-10 (D3): an anonymous provider session is a guest —
      // recognized, never linked, never provisioned, no Payload
      // access. Same liveness gates as `verify` (expiry, admitted
      // channel), minus every user touch.
      return ResultAsync.fromPromise<FoundProviderSession | null, RepositoryError>(
        findProviderSession(deps, headers),
        (cause) => new RepositoryError('guest session read failed', { cause })
      ).map((found) => {
        if (!found || !found.providerSession.identity.anonymous) {
          return null
        }
        if (found.providerSession.expiresAt.getTime() <= deps.clock.now().getTime()) {
          return null
        }
        if (!admitChannels.includes(found.providerSession.channel)) {
          return null
        }
        return {
          id: found.providerSession.providerUserId,
          providerId: found.providerId,
          expiresAt: found.providerSession.expiresAt,
        }
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
