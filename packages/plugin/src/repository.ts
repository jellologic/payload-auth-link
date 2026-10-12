import { err, ok, ResultAsync } from 'neverthrow'
import {
  RepositoryError,
  UserExistsError,
  type ClockPort,
  type CollectionMap,
  type Email,
  type IdPort,
  type LoggerPort,
  type NewUser,
  type ProviderIdentityRef,
  type Role,
  type UserId,
  type UserRecord,
  type UserRepository,
} from '@payload-auth-link/core'
import { ValidationError, type Payload, type Where } from 'payload'
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
  }
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
      return findOne('findByEmail', { [deps.map.emailField]: { equals: email } })
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
      return findOne('linkIdentity:read', { id: { equals: userId } }).andThen((existing) => {
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
            data: { [deps.map.emailField]: email },
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

    setRoles(userId: UserId, roles: readonly Role[]): ResultAsync<UserRecord, RepositoryError> {
      return ResultAsync.fromPromise<unknown, RepositoryError>(
        deps.payload.update({
          collection,
          id: userId,
          data: { [deps.map.rolesField]: [...roles] },
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
