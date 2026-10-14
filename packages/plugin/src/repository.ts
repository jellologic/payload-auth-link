import { err, ok, ResultAsync } from 'neverthrow'
import {
  isRecord,
  RepositoryError,
  UserExistsError,
  type ClockPort,
  type CollectionMap,
  type Email,
  type IdPort,
  type LoggerPort,
  type NewUser,
  type PhoneNumber,
  type ProviderIdentityRef,
  type Role,
  type UserId,
  type UserRecord,
  type UserRepository,
} from '@payload-auth-link/core'
import { ValidationError, type Payload, type Where } from 'payload'
import { linkableCreateMarker } from './collections.js'
import {
  firstResultRecord,
  singleResultRecord,
  toIdentityData,
  toNewUserData,
  type MappingContext,
} from './mapping.js'

/** `UserRepository` over the Payload Local API; depth is always explicit. */
export type PayloadUserRepositoryDeps = {
  readonly payload: Payload
  readonly map: CollectionMap
  readonly defaultRole: Role
  readonly logger: LoggerPort
  readonly clock: ClockPort
  readonly ids: IdPort
  /** Payload query depth for user reads. Always explicit, never hardcoded. */
  readonly depth: number
  /** Governance/identity field names (CAP-7/CAP-9); defaults apply when omitted. */
  readonly userFields?: MappingContext['userFields']
  /** Configured role set (B11); reads drop stored roles outside it. */
  readonly configuredRoles?: ReadonlySet<Role> | undefined
  /** Stored value → canonical role (issue #56); reads translate through it. */
  readonly roleValuesReverse?: Readonly<Record<string, string>> | undefined
  /** Canonical role → stored value (issue #56); writes translate through it. */
  readonly roleValues?: Readonly<Record<string, string>> | undefined
}

function isEmailUniqueViolation(error: unknown, emailField: string): boolean {
  if (!(error instanceof ValidationError)) {
    return false
  }
  return error.data.errors.some(
    (entry) => entry.path === emailField && /unique/i.test(entry.message)
  )
}

/**
 * `UserRepository` over the Payload Local API. Request-scoped: construct one
 * per request from `req.payload` — no shared instances, no init ordering.
 *
 * Reads bypass access control (`overrideAccess`): this is trusted
 * authentication infrastructure resolving the user the access system itself
 * needs. All results are narrowed from `unknown`; nothing is cast.
 */
export function createPayloadUserRepository(deps: PayloadUserRepositoryDeps): UserRepository {
  const ctx: MappingContext = {
    map: deps.map,
    defaultRole: deps.defaultRole,
    logger: deps.logger,
    clock: deps.clock,
    ...(deps.userFields === undefined ? {} : { userFields: deps.userFields }),
    ...(deps.configuredRoles === undefined ? {} : { configuredRoles: deps.configuredRoles }),
    ...(deps.roleValuesReverse === undefined ? {} : { roleValuesReverse: deps.roleValuesReverse }),
    ...(deps.roleValues === undefined ? {} : { roleValues: deps.roleValues }),
  }
  const phoneField = deps.userFields?.phoneField ?? 'phone'
  const collection = deps.map.usersCollection

  const findOne = (
    operation: string,
    where: Where
  ): ResultAsync<UserRecord | null, RepositoryError> =>
    ResultAsync.fromPromise<unknown, RepositoryError>(
      deps.payload.find({
        collection,
        where,
        limit: 1,
        depth: deps.depth,
        pagination: false,
        overrideAccess: true,
      }),
      (cause) => new RepositoryError(operation, { cause })
    ).map((found) => firstResultRecord(found, ctx))

  return {
    findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError> {
      return ResultAsync.fromPromise<unknown, RepositoryError>(
        deps.payload.findByID({ collection, id, depth: deps.depth, overrideAccess: true }),
        (cause) => new RepositoryError('findById', { cause })
      ).map((doc) => singleResultRecord(doc, ctx))
    },

    findByEmail(email: Email): ResultAsync<UserRecord | null, RepositoryError> {
      // JIT-linking proof gate (GHSA-98hq-hh6v-2p2r): email-based
      // resolution may only return documents PROVEN to own that email
      // — the plugin's `linkable` marker (set on plugin-managed and
      // role-manager creates; the migration runbook sets it for
      // imports) or Payload's own verified flag. An unproven document
      // (say, one a stranger pre-created with a victim's email and
      // their own password) is invisible here: the link is refused
      // with a logged reason instead of attaching a verified identity
      // to it.
      return ResultAsync.fromPromise<unknown, RepositoryError>(
        deps.payload.find({
          collection,
          where: { [deps.map.emailField]: { equals: email } },
          limit: 1,
          depth: deps.depth,
          pagination: false,
          overrideAccess: true,
        }),
        (cause) => new RepositoryError('findByEmail', { cause })
      ).map((found) => {
        const doc: unknown = (found as { docs?: unknown[] }).docs?.[0]
        if (!isRecord(doc)) {
          return null
        }
        if (doc.linkable !== true && doc._verified !== true) {
          const docId =
            typeof doc.id === 'string' || typeof doc.id === 'number' ? String(doc.id) : ''
          deps.logger.warn(
            'email link refused: pre-existing document is not marked linkable (was it created outside payload-auth-link?)',
            { email, userId: docId }
          )
          return null
        }
        // GHSA-8524: the linkable proof is bound to the email it was
        // granted for. A self-service email change moves the document
        // email away from the proven address — the proof no longer
        // holds and the link is refused (the plugin's own
        // provider-email resync keeps the two in step).
        if (doc.linkable === true) {
          const provenEmail = typeof doc.linkableEmail === 'string' ? doc.linkableEmail : ''
          const docEmail = typeof doc.email === 'string' ? doc.email : ''
          if (provenEmail === '' || provenEmail.toLowerCase() !== docEmail.toLowerCase()) {
            const docId =
              typeof doc.id === 'string' || typeof doc.id === 'number' ? String(doc.id) : ''
            deps.logger.warn(
              'email link refused: linkable proof does not match the document email (unproven email change?)',
              { email, userId: docId }
            )
            return null
          }
        }
        return singleResultRecord(doc, ctx)
      })
    },

    findByPhone(phone: PhoneNumber): ResultAsync<UserRecord | null, RepositoryError> {
      return findOne('findByPhone', { [phoneField]: { equals: phone } })
    },

    findByProviderIdentity(
      ref: ProviderIdentityRef
    ): ResultAsync<UserRecord | null, RepositoryError> {
      return findOne('findByProviderIdentity', {
        and: [
          { [`${deps.map.identitiesField}.providerId`]: { equals: ref.providerId } },
          { [`${deps.map.identitiesField}.providerUserId`]: { equals: ref.providerUserId } },
        ],
      })
    },

    create(input: NewUser): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
      return ResultAsync.fromPromise<unknown, RepositoryError | UserExistsError>(
        deps.payload.create({
          collection,
          // Unknowable random password: provider users authenticate via
          // their provider, but the password field exists on every auth
          // collection and local-enabled ones require it.
          data: toNewUserData(input, ctx, deps.ids.newId()),
          // Proves plugin-managed creation, so the linkable marker hook
          // marks the document as owning its email (JIT linking proof).
          context: { [linkableCreateMarker]: true },
          overrideAccess: true,
        }),
        (cause) => {
          if (isEmailUniqueViolation(cause, deps.map.emailField)) {
            return new UserExistsError(input.email)
          }
          return new RepositoryError('create', { cause })
        }
      ).andThen((doc) => {
        const record = singleResultRecord(doc, ctx)
        if (!record) {
          return err(new RepositoryError('create: unmappable result'))
        }
        return ok(record)
      })
    },

    linkIdentity(
      userId: UserId,
      ref: ProviderIdentityRef
    ): ResultAsync<UserRecord, RepositoryError> {
      // A document holding a provider identity AND a local password can
      // be signed into by two independent credential owners. The
      // JIT-linking proof gate keeps strangers from arriving here, but
      // a legit local password (host-managed local auth) is worth
      // surfacing to the operator on every link.
      const passwordWarning: ResultAsync<true, RepositoryError> = ResultAsync.fromPromise(
        // Best-effort: a probe outage must never block the link.
        deps.payload
          .findByID({
            collection,
            id: userId,
            depth: 0,
            overrideAccess: true,
            // `hash` is a hidden field: without this the check never
            // sees it and the warning could not fire (GHSA-8524).
            showHiddenFields: true,
          })
          .catch(() => null),
        () => new RepositoryError('linkIdentity:password-check')
      ).map((doc) => {
        if (isRecord(doc) && typeof doc.hash === 'string' && doc.hash !== '') {
          deps.logger.warn(
            'identity linked to a document that also holds a local password; ensure both credential owners are the same person',
            { userId, providerId: ref.providerId }
          )
        }
        return true
      })
      return passwordWarning.andThen(() =>
        findOne('linkIdentity:read', { id: { equals: userId } }).andThen((existing) => {
          if (!existing) {
            return err(new RepositoryError(`linkIdentity: user not found: ${userId}`))
          }
          if (
            existing.identities.some(
              (identity) =>
                identity.providerId === ref.providerId &&
                identity.providerUserId === ref.providerUserId
            )
          ) {
            deps.logger.info('identity already linked', { userId, providerId: ref.providerId })
            return ok(existing)
          }
          const rows = [
            ...existing.identities.map((identity) => ({
              providerId: identity.providerId,
              providerUserId: identity.providerUserId,
              email: identity.email,
              linkedAt: identity.linkedAt.toISOString(),
            })),
            toIdentityData(ref, existing.email, deps.clock),
          ]
          return ResultAsync.fromPromise<unknown, RepositoryError>(
            deps.payload.update({
              collection,
              id: userId,
              data: { [deps.map.identitiesField]: rows },
              overrideAccess: true,
            }),
            (cause) => new RepositoryError('linkIdentity:update', { cause })
          ).andThen((doc) => {
            const record = singleResultRecord(doc, ctx)
            if (!record) {
              return err(new RepositoryError('linkIdentity: unmappable result'))
            }
            return ok(record)
          })
        })
      )
    },

    unlinkIdentity(
      userId: UserId,
      ref: ProviderIdentityRef
    ): ResultAsync<UserRecord, RepositoryError> {
      return findOne('unlinkIdentity:read', { id: { equals: userId } }).andThen((existing) => {
        if (!existing) {
          return err(new RepositoryError(`unlinkIdentity: user not found: ${userId}`))
        }
        const rows = existing.identities.filter(
          (identity) =>
            identity.providerId !== ref.providerId || identity.providerUserId !== ref.providerUserId
        )
        if (rows.length === existing.identities.length) {
          // Idempotent: the identity is already unlinked (CAP-14).
          return ok(existing)
        }
        return ResultAsync.fromPromise<unknown, RepositoryError>(
          deps.payload.update({
            collection,
            id: userId,
            data: {
              [deps.map.identitiesField]: rows.map((identity) => ({
                providerId: identity.providerId,
                providerUserId: identity.providerUserId,
                email: identity.email,
                linkedAt: identity.linkedAt.toISOString(),
              })),
            },
            overrideAccess: true,
          }),
          (cause) => new RepositoryError('unlinkIdentity:update', { cause })
        ).andThen((doc) => {
          const record = singleResultRecord(doc, ctx)
          if (!record) {
            return err(new RepositoryError('unlinkIdentity: unmappable result'))
          }
          return ok(record)
        })
      })
    },

    setEmail(
      userId: UserId,
      email: Email
    ): ResultAsync<UserRecord, RepositoryError | UserExistsError> {
      return findOne('setEmail:read', { id: { equals: userId } }).andThen((existing) => {
        if (!existing) {
          return err(new RepositoryError(`setEmail: user not found: ${userId}`))
        }
        if (existing.email === email) {
          return ok(existing)
        }
        return ResultAsync.fromPromise<unknown, RepositoryError | UserExistsError>(
          deps.payload.update({
            collection,
            id: userId,
            data: {
              [deps.map.emailField]: email,
              // The provider verified this new address before the
              // resync: the linkable proof moves with it (GHSA-8524).
              linkable: true,
              linkableEmail: email,
              // Keep the linked-identity rows in step (issue #21):
              // rows carrying the old address are the same identity
              // re-asserted at the new address; leaving them stale
              // shows the old email in the admin view and makes the
              // identity row disagree with the user it belongs to.
              [deps.map.identitiesField]: existing.identities.map((identity) => ({
                providerId: identity.providerId,
                providerUserId: identity.providerUserId,
                email: identity.email === existing.email ? email : identity.email,
                linkedAt: identity.linkedAt.toISOString(),
              })),
            },
            overrideAccess: true,
          }),
          (cause) => {
            if (isEmailUniqueViolation(cause, deps.map.emailField)) {
              return new UserExistsError(email)
            }
            return new RepositoryError('setEmail', { cause })
          }
        ).andThen((doc) => {
          const record = singleResultRecord(doc, ctx)
          if (!record) {
            return err(new RepositoryError('setEmail: unmappable result'))
          }
          return ok(record)
        })
      })
    },

    setPhone(userId: UserId, phone: PhoneNumber): ResultAsync<UserRecord, RepositoryError> {
      return findOne('setPhone:read', { id: { equals: userId } }).andThen((existing) => {
        if (!existing) {
          return err(new RepositoryError(`setPhone: user not found: ${userId}`))
        }
        if (existing.phone === phone) {
          return ok(existing)
        }
        // A verified claim must never steal another user's link
        // target: refuse when the number is already on file elsewhere.
        return findOne('setPhone:conflict', { [phoneField]: { equals: phone } }).andThen(
          (holder) => {
            if (holder && holder.id !== userId) {
              return err(new RepositoryError('setPhone: phone already held by another user'))
            }
            return ResultAsync.fromPromise<unknown, RepositoryError>(
              deps.payload.update({
                collection,
                id: userId,
                data: { [phoneField]: phone },
                overrideAccess: true,
              }),
              (cause) => new RepositoryError('setPhone', { cause })
            ).andThen((doc) => {
              const record = singleResultRecord(doc, ctx)
              if (!record) {
                return err(new RepositoryError('setPhone: unmappable result'))
              }
              return ok(record)
            })
          }
        )
      })
    },

    setRoles(userId: UserId, roles: readonly Role[]): ResultAsync<UserRecord, RepositoryError> {
      return ResultAsync.fromPromise<unknown, RepositoryError>(
        deps.payload.update({
          collection,
          id: userId,
          // Storage edge (issue #56): canonical roles persist as their
          // stored values.
          data: {
            [deps.map.rolesField]: roles.map((role) => deps.roleValues?.[role] ?? role),
          },
          overrideAccess: true,
        }),
        (cause) => new RepositoryError('setRoles', { cause })
      ).andThen((doc) => {
        const record = singleResultRecord(doc, ctx)
        if (!record) {
          return err(new RepositoryError('setRoles: unmappable result'))
        }
        return ok(record)
      })
    },
  }
}
