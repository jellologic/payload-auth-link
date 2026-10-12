import {
  defineUserId,
  isRecord,
  parseEmail,
  parseRole,
  providerIdSchema,
  toDate,
  type ClockPort,
  type CollectionMap,
  type LinkedIdentity,
  type LoggerPort,
  type NewUser,
  type ProviderIdentityRef,
  type Role,
  type SessionUser,
  type UserRecord,
} from '@payload-auth-link/core'

/** Shared mapping inputs: slug map, default role, leaf ports. */
export type MappingContext = {
  readonly map: CollectionMap
  readonly defaultRole: Role
  readonly logger: LoggerPort
  readonly clock: ClockPort
}

function toIdentityRow(row: unknown, email: string, ctx: MappingContext): LinkedIdentity | null {
  if (!isRecord(row)) {
    ctx.logger.warn('dropping malformed identity row: not an object')
    return null
  }
  const providerId = providerIdSchema.safeParse(row.providerId)
  if (!providerId.success) {
    ctx.logger.warn('dropping identity row: invalid providerId')
    return null
  }
  if (typeof row.providerUserId !== 'string' || row.providerUserId === '') {
    ctx.logger.warn('dropping identity row: invalid providerUserId')
    return null
  }
  const parsedEmail = parseEmail(row.email ?? email)
  if (parsedEmail.isErr()) {
    ctx.logger.warn('dropping identity row: invalid email')
    return null
  }
  const linkedAt = toDate(row.linkedAt)
  if (!linkedAt) {
    ctx.logger.warn('dropping identity row: invalid linkedAt')
    return null
  }
  return {
    providerId: providerId.data,
    providerUserId: row.providerUserId,
    email: parsedEmail.value,
    linkedAt,
  }
}

/**
 * Narrow persisted roles. `undefined` (legacy docs predating the field)
 * grandfathers to the default role; anything defined must yield at
 * least one valid role, otherwise the record is denied (`null`) —
 * upgrading an emptied or corrupt roles array to the default would
 * mint access the stored data does not grant.
 */
function toRoles(value: unknown, ctx: MappingContext): readonly Role[] | null {
  if (value === undefined) {
    return [ctx.defaultRole]
  }
  if (!Array.isArray(value)) {
    ctx.logger.warn('cannot map user doc: roles field is not an array')
    return null
  }
  const roles: Role[] = []
  for (const entry of value) {
    const parsed = parseRole(entry)
    if (parsed.isErr()) {
      ctx.logger.warn('dropping invalid role entry')
      continue
    }
    roles.push(parsed.value)
  }
  if (roles.length === 0) {
    ctx.logger.warn('cannot map user doc: no valid roles')
    return null
  }
  return roles
}

/**
 * Narrow a Payload user document to a {@link UserRecord}. Returns `null`
 * when the document cannot honestly become a record (missing id/email/
 * timestamps, or defined-but-unmappable roles). Malformed identities
 * are dropped with a warning and never silently kept.
 */
export function toUserRecord(doc: unknown, ctx: MappingContext): UserRecord | null {
  if (!isRecord(doc)) {
    ctx.logger.warn('cannot map user doc: not an object')
    return null
  }
  const rawId = doc.id
  if ((typeof rawId !== 'string' && typeof rawId !== 'number') || rawId === '') {
    ctx.logger.warn('cannot map user doc: invalid id')
    return null
  }
  const email = parseEmail(doc[ctx.map.emailField])
  if (email.isErr()) {
    ctx.logger.warn('cannot map user doc: invalid email')
    return null
  }
  const createdAt = toDate(doc.createdAt)
  const updatedAt = toDate(doc.updatedAt)
  if (!createdAt || !updatedAt) {
    ctx.logger.warn('cannot map user doc: invalid timestamps')
    return null
  }
  const roles = toRoles(doc[ctx.map.rolesField], ctx)
  if (!roles) {
    return null
  }
  const rawIdentities = doc[ctx.map.identitiesField]
  const identities: LinkedIdentity[] = []
  if (rawIdentities !== undefined) {
    if (!Array.isArray(rawIdentities)) {
      ctx.logger.warn('identities field is not an array; treating as empty')
    } else {
      for (const row of rawIdentities) {
        const identity = toIdentityRow(row, email.value, ctx)
        if (identity) {
          identities.push(identity)
        }
      }
    }
  }
  return {
    id: defineUserId(String(rawId)),
    email: email.value,
    roles,
    identities,
    createdAt,
    updatedAt,
  }
}

/**
 * Pull the first document from a paginated `find` result and narrow it.
 * Returns `null` for empty results or unmappable docs.
 */
export function firstResultRecord(result: unknown, ctx: MappingContext): UserRecord | null {
  if (!isRecord(result) || !Array.isArray(result.docs)) {
    ctx.logger.warn('cannot map find result: missing docs array')
    return null
  }
  const docs: unknown[] = result.docs
  const [first] = docs
  if (first === undefined) {
    return null
  }
  return toUserRecord(first, ctx)
}

/** Narrow a single-document result (`findByID`, `create`, `update`). */
export function singleResultRecord(doc: unknown, ctx: MappingContext): UserRecord | null {
  return toUserRecord(doc, ctx)
}

/**
 * Build `payload.create` data for a new user. `password` must be an
 * unknowable random value (see `createPayloadUserRepository`): provider
 * users never log in with it, but local-enabled collections require the
 * field and SSO collections keep it for continuity.
 */
export function toNewUserData(
  input: NewUser,
  ctx: Pick<MappingContext, 'map' | 'clock'>,
  password: string
): Record<string, unknown> {
  return {
    [ctx.map.emailField]: input.email,
    password,
    [ctx.map.rolesField]: [...input.roles],
    [ctx.map.identitiesField]:
      input.identity === undefined ? [] : [toIdentityData(input.identity, input.email, ctx.clock)],
  }
}

/** Build one identities-array row for writes. */
export function toIdentityData(
  ref: ProviderIdentityRef,
  email: string,
  clock: ClockPort
): Record<string, unknown> {
  return {
    providerId: ref.providerId,
    providerUserId: ref.providerUserId,
    email,
    linkedAt: clock.now().toISOString(),
  }
}

/**
 * The user object the auth strategy hands to Payload. Satisfies `BaseUser`
 * (`id`, `collection`, `email`) plus our domain fields. This is the shared
 * {@link SessionUser} wire shape: the session endpoint serializes it and
 * the UI adapters hydrate from it.
 */
export type PayloadAuthUser = SessionUser

/** Project a user record to the session wire shape (roles defensively copied). */
export function toPayloadUser(record: UserRecord, collection: string): PayloadAuthUser {
  return {
    id: record.id,
    collection,
    email: record.email,
    roles: [...record.roles],
  }
}
