import { err, errAsync, ok, okAsync, ResultAsync } from 'neverthrow'
import {
  authLinkWriteMarker,
  isRecord,
  RepositoryError,
  UserExistsError,
  type AuthLinkWriteMarker,
  type AuthLinkWriteOp,
  type ClockPort,
  type CollectionMap,
  type Email,
  type IdPort,
  type LoggerPort,
  type NewUser,
  type PhoneNumber,
  type ProviderId,
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
  /**
   * Keep the document's local credentials (Payload API key) when a
   * provider identity links to it. Mirrors the plugin's
   * `allowLocalCredentialsForLinkedDocs`; by default linking clears a
   * Payload API key enabled before the link.
   */
  readonly keepLocalCredentialsOnLink?: boolean | undefined
  /**
   * Whether one provider's user ids ARE the users-collection document
   * ids (adopt mode, `idStrategy: 'payload'` — the port fact
   * `providerUserIdsAreDocumentIds`). Only a provider answering true
   * gets the `findByProviderOwnedId` id-linking path (issue #124);
   * absent or false, JIT linking never resolves by document id.
   */
  readonly providerOwnedUserIds?: ((providerId: ProviderId) => boolean) | undefined
  /**
   * Observer for the users-document writes this repository actually
   * performs — called once per successful write, never for a no-op
   * (an identity already linked, an unchanged email or phone) and
   * never for a lost create race (`UserExistsError`). The session
   * service audits impersonated verification through it (issue #116).
   */
  readonly onWrite?: ((write: UserDocumentWrite) => void) | undefined
}

/** A users-document write the repository performed (see `onWrite`). */
export type UserDocumentWrite = {
  readonly operation: 'create' | 'linkIdentity' | 'setEmail' | 'setPhone'
  readonly userId: UserId
}

/**
 * An email collision, in either spelling Payload produces: the
 * database's unique index ("Value must be unique") or, on auth
 * collections with the local strategy, Payload's own pre-insert check
 * ("A user with the given email is already registered."). Both map to
 * the typed `UserExistsError`, never a raw storage error.
 */
/**
 * Whether a repository failure is Payload's "no document with that
 * id". Structural, not `instanceof` (see {@link isEmailUniqueViolation}
 * for why): the probe in {@link findByProviderOwnedId} reads a miss as
 * `null` and lets only real failures through.
 */
function isNotFound(error: RepositoryError): boolean {
  const cause: unknown = error.cause
  return isRecord(cause) && (cause.name === 'NotFoundError' || cause.status === 404)
}

function isEmailUniqueViolation(error: unknown, emailField: string): boolean {
  // Structural, not `instanceof`: the host app and the plugin can load
  // different copies of `payload` (e.g. a Payload v4 app with the plugin
  // resolving v3 types), and `instanceof` fails across copies — the
  // collision then surfaced as a raw storage error and the lost-create
  // race retry never ran (the second of two concurrent first requests
  // after sign-up came back signed out).
  const isValidationError =
    error instanceof ValidationError || (isRecord(error) && error.name === 'ValidationError')
  if (!isValidationError || !isRecord(error) || !isRecord(error.data)) {
    return false
  }
  const errors = error.data.errors
  return (
    Array.isArray(errors) &&
    errors.some(
      (entry: unknown) =>
        isRecord(entry) &&
        entry.path === emailField &&
        typeof entry.message === 'string' &&
        /unique|already registered/i.test(entry.message)
    )
  )
}

/**
 * Whether the users collection keeps Payload's server-side local
 * sessions (`auth.useSessions`, Payload's default): a local JWT is
 * honored only while its `sid` is in the document's `sessions` array.
 */
function collectionUsesLocalSessions(payload: Payload, slug: string): boolean {
  const collections: unknown = (payload as { collections?: unknown }).collections
  if (!isRecord(collections)) {
    return false
  }
  const entry = collections[slug]
  if (!isRecord(entry) || !isRecord(entry.config) || !isRecord(entry.config.auth)) {
    return false
  }
  return entry.config.auth.useSessions === true
}

/**
 * Whether the users collection carries Payload's API-key credential
 * (`auth.useAPIKey`), and whether its field set still includes the
 * legacy `enableAPIKey` toggle (Payload v3; v4 keys on `apiKey` alone).
 */
function collectionApiKeyShape(
  payload: Payload,
  slug: string
): { readonly useAPIKey: boolean; readonly enableField: boolean } {
  const collections: unknown = (payload as { collections?: unknown }).collections
  const entry = isRecord(collections) ? collections[slug] : undefined
  if (!isRecord(entry) || !isRecord(entry.config) || !isRecord(entry.config.auth)) {
    return { useAPIKey: false, enableField: false }
  }
  const fields: unknown = entry.config.fields
  return {
    useAPIKey: entry.config.auth.useAPIKey === true,
    enableField:
      Array.isArray(fields) &&
      fields.some((field: unknown) => isRecord(field) && field.name === 'enableAPIKey'),
  }
}

/**
 * The `context` argument every plugin-initiated Local API write passes
 * (issue #144, mirroring the migrate kit's `MIGRATION_CONTEXT`):
 * Payload merges it into `req.context`, where host hooks read it to
 * skip their outward side effects for the plugin's bookkeeping writes
 * (see {@link authLinkWriteMarker}). The adapter writes beside them
 * (`payload.db.updateOne` in {@link scopedUpdate}) run no hooks and
 * carry no marker.
 */
function writeContextOf(op: AuthLinkWriteOp): {
  readonly context: { readonly [authLinkWriteMarker]: AuthLinkWriteMarker }
} {
  return { context: { [authLinkWriteMarker]: { op } } }
}

/** A database transaction id, as `payload.db.beginTransaction` returns it. */
export type TransactionId = string | number

/**
 * The adapter's transaction API, reached structurally: absent on some
 * adapters, so the scoped writes below degrade to per-statement
 * transactions there (the migrate kit ships the same probe in its
 * `inTransaction`).
 */
type TransactionApi = {
  readonly beginTransaction: () => Promise<TransactionId | null>
  readonly commitTransaction: (id: TransactionId) => Promise<void>
  readonly rollbackTransaction: (id: TransactionId) => Promise<void>
}

function transactionApi(payload: Payload): TransactionApi | null {
  const db: unknown = (payload as { db?: unknown }).db
  if (
    typeof db === 'object' &&
    db !== null &&
    typeof (db as Record<string, unknown>)['beginTransaction'] === 'function' &&
    typeof (db as Record<string, unknown>)['commitTransaction'] === 'function' &&
    typeof (db as Record<string, unknown>)['rollbackTransaction'] === 'function'
  ) {
    return db as unknown as TransactionApi
  }
  return null
}

/**
 * Run `work` inside ONE adapter transaction when the adapter provides
 * one (Postgres, SQLite; MongoDB on a replica set), committing when it
 * resolves and rolling back when it throws. The scoped writes replace
 * Local API updates — which Payload wraps in its own fresh
 * transaction (`initTransaction`) — so the adapter's multi-statement
 * upsert (main row, then child rows) keeps its all-or-nothing
 * behavior.
 */
async function inTransaction<T>(
  payload: Payload,
  work: (transactionID: TransactionId | null) => Promise<T>
): Promise<T> {
  const api = transactionApi(payload)
  const id = api === null ? null : await api.beginTransaction()
  if (api === null || id === null) {
    return work(null)
  }
  let result: T
  try {
    result = await work(id)
  } catch (error) {
    await api.rollbackTransaction(id)
    throw error
  }
  await api.commitTransaction(id)
  return result
}

/** An adapter `req` carrying the transaction, or nothing. */
function transactionReq(
  transactionID: TransactionId | null
): { readonly req: { readonly transactionID: TransactionId } } | Record<string, never> {
  return transactionID === null ? {} : { req: { transactionID } }
}

/**
 * Write ONLY the given (plugin-owned) fields, straight through the
 * database adapter (issue #144 part 1). `payload.update` runs
 * full-document validation — it merges the stored document into the
 * incoming data and validates every field — so a legacy row failing
 * ANY unrelated required field (a host that made `name` required
 * after the row was created) could never receive an identity link,
 * and the user could not sign in. The adapter path writes exactly the
 * given fields: Payload's own update operation feeds the same
 * `db.updateOne` after hooks and validation, so unrelated validation
 * never runs here.
 *
 * `data` is a LIST of payloads written in order inside ONE adapter
 * transaction ({@link inTransaction}); the last write's document is
 * returned. The split is load-bearing on the SQL adapters: a payload
 * with array fields (`identities`, `sessions`) rewrites child rows
 * and must carry NO main-row columns, because the adapter reaches
 * child rows through a full-document upsert whose INSERT branch would
 * have to satisfy every NOT NULL column from partial data; a payload
 * with only plain columns takes the adapter's plain-UPDATE path and
 * touches exactly those columns. So: credential columns first,
 * identity rows last, and the final read-back sees both.
 *
 * Parity with the operation write this replaces, spelled out:
 * - Row `id`s for array rows must be SUPPLIED: Payload mints them in
 *   the `id` field's `beforeChange` hook (`baseIDField`), and on SQL
 *   the child table's `id` is a NOT NULL PRIMARY KEY with no default.
 *   Callers include a freshly minted id per row (the operation minted
 *   fresh ids on every write too, because the repository's rows never
 *   carried them).
 * - Payload's `apiKeyIndex` lookup column is nulled EXPLICITLY when a
 *   key is revoked: the Local API does that through its
 *   `setAPIKeyIndex` field hook, and no hook runs here — left stale,
 *   the HMAC would still authenticate (the API-key strategy matches
 *   on the index alone).
 * - `updatedAt` is not stamped: the adapter writes no timestamps of
 *   its own. Hosts keying caches on `updated_at` see identity
 *   bookkeeping as silent — the migrate kit's scoped writes make the
 *   same choice deliberately.
 * - No version row is created for hosts with `versions` on the users
 *   collection (the operation would have created one).
 * - No hook fires, so no host hook can veto or observe the write;
 *   that is why these writes carry no {@link authLinkWriteMarker}.
 */
function scopedUpdate(
  payload: Payload,
  options: {
    readonly collection: string
    readonly id: string | number
    readonly data: readonly Record<string, unknown>[]
    /** The failing operation's name for the `RepositoryError`. */
    readonly operation: string
  }
): ResultAsync<unknown, RepositoryError> {
  return ResultAsync.fromPromise<unknown, RepositoryError>(
    inTransaction(payload, async (transactionID) => {
      let result: unknown = null
      for (const data of options.data) {
        result = await payload.db.updateOne({
          collection: options.collection,
          id: options.id,
          data,
          ...transactionReq(transactionID),
        })
      }
      return result
    }),
    (cause) => new RepositoryError(options.operation, { cause })
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

  const findById = (id: string): ResultAsync<UserRecord | null, RepositoryError> =>
    ResultAsync.fromPromise<unknown, RepositoryError>(
      deps.payload.findByID({ collection, id, depth: deps.depth, overrideAccess: true }),
      (cause) => new RepositoryError('findById', { cause })
    ).map((doc) => singleResultRecord(doc, ctx))

  return {
    findById(id: UserId): ResultAsync<UserRecord | null, RepositoryError> {
      return findById(String(id))
    },

    findByEmail(email: Email): ResultAsync<UserRecord | null, RepositoryError> {
      // JIT-linking proof gate (GHSA-98hq-hh6v-2p2r): email-based
      // resolution may only return documents PROVEN to own that email
      // — the plugin's `linkable` marker (set on plugin-managed and
      // role-manager creates; the migration importer sets it for
      // verified imports), bound to the address it was granted for
      // (`linkableEmail`). Payload's own `_verified` flag is NOT proof
      // on its own: Payload keeps it across email changes (and its
      // default field access lets any signed-in user write it), so a
      // verified document re-pointed at someone else's address would
      // otherwise be handed their identity. An unproven document is
      // invisible here: the link is refused with a logged reason
      // instead of attaching a verified identity to it.
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
        const docId = typeof doc.id === 'string' || typeof doc.id === 'number' ? String(doc.id) : ''
        if (doc.linkable !== true) {
          deps.logger.warn(
            doc._verified === true
              ? "email link refused: an existing document holds this email without an ownership proof (Payload's verified flag is not one); an operator must resolve the collision: confirm who created and owns that document, then rename or remove it if it is not the address owner's (a verification mail proves the address, not the document)"
              : "email link refused: an existing document holds this email without an ownership proof (created outside payload-auth-link?); an operator must resolve the collision: confirm who created and owns that document, then rename or remove it if it is not the address owner's (a verification mail proves the address, not the document)",
            { email, userId: docId }
          )
          return null
        }
        // GHSA-8524: the linkable proof is bound to the email it was
        // granted for. A self-service email change moves the document
        // email away from the proven address (and resets the proof) —
        // the link is refused (the plugin's own provider-email resync
        // keeps the two in step).
        const provenEmail = typeof doc.linkableEmail === 'string' ? doc.linkableEmail : ''
        const docEmail = typeof doc.email === 'string' ? doc.email : ''
        if (provenEmail === '' || provenEmail.toLowerCase() !== docEmail.toLowerCase()) {
          deps.logger.warn(
            "email link refused: linkable proof does not match the document email (unproven email change?); an operator must confirm the document is the address owner's before re-granting the proof",
            { email, userId: docId }
          )
          return null
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

    ...(deps.providerOwnedUserIds === undefined
      ? {}
      : {
          // Adopt mode (issue #124): the engine writes user rows with
          // its own user id AS the Payload document id, so the row a
          // fresh sign-up creates resolves by id and only by id. The
          // gate is per provider (see the dep): a provider whose
          // engine mints its own row ids never resolves here. A MISS
          // is `null`, not a storage error — this is a probe, and the
          // linking use case falls through on it; only a real storage
          // failure propagates.
          findByProviderOwnedId(ref: ProviderIdentityRef) {
            if (deps.providerOwnedUserIds?.(ref.providerId) !== true) {
              return okAsync(null)
            }
            return findById(String(ref.providerUserId)).orElse((error) =>
              isNotFound(error) ? okAsync(null) : errAsync(error)
            )
          },
        }),

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
          // The write marker (issue #144) lets host hooks skip their
          // outward side effects for the plugin's bookkeeping creates.
          context: {
            [linkableCreateMarker]: true,
            [authLinkWriteMarker]: { op: 'create' },
          },
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
        deps.onWrite?.({ operation: 'create', userId: record.id })
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
              // The adapter runs no field hooks, so the `id` each
              // identities row carries in storage (Payload's
              // `baseIDField`, the child table's PRIMARY KEY on SQL)
              // must be minted here — the old Local API write minted a
              // fresh one per row on every write too.
              id: deps.ids.newId(),
              providerId: identity.providerId,
              providerUserId: identity.providerUserId,
              email: identity.email,
              linkedAt: identity.linkedAt.toISOString(),
            })),
            { id: deps.ids.newId(), ...toIdentityData(ref, existing.email, deps.clock) },
          ]
          // The document becomes (more) provider-owned: local
          // sessions issued BEFORE the link must not survive it — a
          // pre-link local JWT belongs to whoever held the document
          // before the provider's verified owner arrived. Clearing
          // Payload's `sessions` array kills every such JWT on its
          // next request (hosts without `useSessions` are covered by
          // the provider-owned local-JWT gate in collections.ts).
          const revokeLocalSessions = collectionUsesLocalSessions(deps.payload, collection)
          // A Payload API key enabled before the link is a local
          // credential of the same kind: it is cleared in the same
          // write, unless the host keeps local credentials on linked
          // documents. The provider-owned gate in collections.ts
          // refuses any key that survives (e.g. a later re-enable).
          const apiKeyShape = collectionApiKeyShape(deps.payload, collection)
          const revokeApiKey = apiKeyShape.useAPIKey && deps.keepLocalCredentialsOnLink !== true
          // Scoped write (issue #144 part 1): ONLY the plugin-owned
          // fields go to the adapter, split as {@link scopedUpdate}
          // requires — credential columns first (plain-UPDATE path,
          // including the `apiKeyIndex` lookup column that the Local
          // API's `setAPIKeyIndex` field hook would have nulled), the
          // identity rows and session clearing last (child-row
          // rewrite). The Local API's full-document validation would
          // fail the link — and with it the sign-in — for a document
          // that fails an unrelated required field; no hook fires
          // here, so nothing host-side can veto the write either.
          return scopedUpdate(deps.payload, {
            collection,
            id: userId,
            data: [
              ...(revokeApiKey
                ? [
                    {
                      apiKey: null,
                      apiKeyIndex: null,
                      ...(apiKeyShape.enableField ? { enableAPIKey: false } : {}),
                    },
                  ]
                : []),
              {
                [deps.map.identitiesField]: rows,
                ...(revokeLocalSessions ? { sessions: [] } : {}),
              },
            ],
            operation: 'linkIdentity:update',
          }).andThen((doc) => {
            if (revokeLocalSessions) {
              deps.logger.info('local sessions revoked on identity link', {
                userId,
                providerId: ref.providerId,
              })
            }
            if (revokeApiKey) {
              deps.logger.info('local API key cleared on identity link', {
                userId,
                providerId: ref.providerId,
              })
            }
            const record = singleResultRecord(doc, ctx)
            if (!record) {
              return err(new RepositoryError('linkIdentity: unmappable result'))
            }
            deps.onWrite?.({ operation: 'linkIdentity', userId: record.id })
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
        // Scoped write (issue #144 part 1): only the identities field,
        // straight through the adapter — the full-document operation
        // would refuse a document that fails an unrelated required
        // field. No hook relied on this write (no email moves, no
        // credential state changes), and none fires. The rows carry
        // freshly minted ids: the adapter runs no field hooks to mint
        // them (see linkIdentity).
        return scopedUpdate(deps.payload, {
          collection,
          id: userId,
          data: [
            {
              [deps.map.identitiesField]: rows.map((identity) => ({
                id: deps.ids.newId(),
                providerId: identity.providerId,
                providerUserId: identity.providerUserId,
                email: identity.email,
                linkedAt: identity.linkedAt.toISOString(),
              })),
            },
          ],
          operation: 'unlinkIdentity:update',
        }).andThen((doc) => {
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
        // This write keeps the Local API on purpose (issue #144): it
        // moves the document email, and the collection's
        // `resetProofOnEmailChange` hook (GHSA-8524) is the guard that
        // clears every proof when an email moves WITHOUT re-granting
        // it in the same write. The re-grant fields below satisfy the
        // hook today; if a refactor ever dropped them, the hook — not
        // this code — would still refuse to let a stale proof ride a
        // moved address. The adapter path runs no hooks, so it would
        // silently lose that safety net (plus Payload's email
        // validation and the unique-violation mapping below).
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
            // The write marker (issue #144 part 2): host hooks skip
            // their outward side effects for the plugin's resync.
            ...writeContextOf('resync-email'),
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
          deps.onWrite?.({ operation: 'setEmail', userId: record.id })
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
            // Local API on purpose (issue #144): the plugin's phone
            // field validates E.164 in its own `validate`, and host
            // hooks observe the change; the write marker (issue #144
            // part 2) lets them skip their outward side effects.
            return ResultAsync.fromPromise<unknown, RepositoryError>(
              deps.payload.update({
                collection,
                id: userId,
                data: { [phoneField]: phone },
                ...writeContextOf('resync-phone'),
                overrideAccess: true,
              }),
              (cause) => new RepositoryError('setPhone', { cause })
            ).andThen((doc) => {
              const record = singleResultRecord(doc, ctx)
              if (!record) {
                return err(new RepositoryError('setPhone: unmappable result'))
              }
              deps.onWrite?.({ operation: 'setPhone', userId: record.id })
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
          // The write marker (issue #144 part 2): host hooks skip
          // their outward side effects for the plugin's role writes.
          ...writeContextOf('set-roles'),
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
