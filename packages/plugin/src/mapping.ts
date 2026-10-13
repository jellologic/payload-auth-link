import {
  assertNever,
  defineUserId,
  effectiveRoles,
  isRecord,
  parseEmail,
  parsePhoneNumber,
  parseRole,
  providerIdSchema,
  toDate,
  withheldRoles,
  type ClockPort,
  type CollectionMap,
  type LinkedIdentity,
  type LoggerPort,
  type NewUser,
  type ProviderIdentityRef,
  type Role,
  type Session,
  type SessionUser,
  type UserRecord,
} from '@payload-auth-link/core'

/** Shared mapping inputs: slug map, default role, leaf ports. */
export type MappingContext = {
  readonly map: CollectionMap
  readonly defaultRole: Role
  readonly logger: LoggerPort
  readonly clock: ClockPort
  /**
   * Governance/identity field names (CAP-7/CAP-9). Optional so direct
   * mapping callers keep working; absent means the plugin defaults
   * (`phone`, `suspendedUntil`, `suspendReason`).
   */
  readonly userFields?:
    | {
        readonly phoneField: string
        readonly suspendedUntilField: string
        readonly suspendReasonField: string
      }
    | undefined
}

const defaultUserFields = {
  phoneField: 'phone',
  suspendedUntilField: 'suspendedUntil',
  suspendReasonField: 'suspendReason',
} as const

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
  const fields = ctx.userFields ?? defaultUserFields
  // Phone (CAP-9): absent/null -> null; a present-but-invalid value is
  // dropped with a warning (never trusted for linking), without
  // nuking an otherwise valid user record.
  let phone: UserRecord['phone'] = null
  const rawPhone: unknown = doc[fields.phoneField]
  if (rawPhone !== undefined && rawPhone !== null && rawPhone !== '') {
    const parsedPhone = parsePhoneNumber(rawPhone)
    if (parsedPhone.isOk()) {
      phone = parsedPhone.value
    } else {
      ctx.logger.warn('dropping invalid stored phone value')
    }
  }
  // Suspension (CAP-7): a present-but-unparseable date fails CLOSED —
  // the record is denied rather than admitting a possibly-suspended
  // user. Absent/null is the only "not suspended" spelling.
  let suspendedUntil: Date | null = null
  const rawSuspended: unknown = doc[fields.suspendedUntilField]
  if (rawSuspended !== undefined && rawSuspended !== null) {
    suspendedUntil = toDate(rawSuspended)
    if (!suspendedUntil) {
      ctx.logger.warn('cannot map user doc: invalid suspendedUntil')
      return null
    }
  }
  const rawReason: unknown = doc[fields.suspendReasonField]
  const suspendReason = typeof rawReason === 'string' && rawReason !== '' ? rawReason : null
  return {
    id: defineUserId(String(rawId)),
    email: email.value,
    roles,
    identities,
    createdAt,
    updatedAt,
    phone,
    suspendedUntil,
    suspendReason,
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
  ctx: Pick<MappingContext, 'map' | 'clock' | 'userFields'>,
  password: string
): Record<string, unknown> {
  const phoneField = (ctx.userFields ?? defaultUserFields).phoneField
  return {
    [ctx.map.emailField]: input.email,
    password,
    [ctx.map.rolesField]: [...input.roles],
    [ctx.map.identitiesField]:
      input.identity === undefined ? [] : [toIdentityData(input.identity, input.email, ctx.clock)],
    ...(input.phone === undefined ? {} : { [phoneField]: input.phone }),
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

/**
 * The PORT-4 session facts a {@link Session} carries onto the wire.
 * Structurally the optional tail of `Session`, so callers pass the
 * verified session itself.
 */
export type SessionUserFacts = Pick<Session, 'assurance' | 'actor' | 'organizationId'>

/** Defensive copy of the resolved actor discriminated union. */
function copyActor(actor: NonNullable<Session['actor']>): NonNullable<Session['actor']> {
  switch (actor.kind) {
    case 'payload-user':
      return { kind: 'payload-user', providerUserId: actor.providerUserId, userId: actor.userId }
    case 'provider-only':
      return { kind: 'provider-only', providerUserId: actor.providerUserId }
    default:
      return assertNever(actor)
  }
}

/**
 * Project a user record to the session wire shape (roles defensively
 * copied). `facts` carries the verified session's PORT-4 fields:
 * each is copied only when present, so an absent fact stays absent
 * on the wire (never `null`, never a fabricated default), while a
 * reported `assurance` — including `'unknown'` values — serializes
 * as data. Omitting `facts` yields exactly the pre-PORT-4 shape.
 */
export function toPayloadUser(
  record: UserRecord,
  collection: string,
  facts?: SessionUserFacts,
  policies?: { readonly requireMfaForRoles?: readonly Role[] | undefined }
): PayloadAuthUser {
  // CAP-6: roles listed in `requireMfaForRoles` are withheld from
  // sessions without MFA proof (core `effectiveRoles`, fail-closed on
  // absent/'unknown' assurance). Stored roles are untouched; the
  // wire gains `mfaRequired: true` exactly when something was withheld.
  const gated = policies?.requireMfaForRoles ?? []
  const roles = effectiveRoles(record.roles, facts?.assurance, gated)
  const withheld = withheldRoles(record.roles, facts?.assurance, gated)
  return {
    id: record.id,
    collection,
    email: record.email,
    roles: [...roles],
    ...(withheld.length > 0 ? { mfaRequired: true as const } : {}),
    ...(facts?.assurance === undefined
      ? {}
      : {
          assurance: {
            methods:
              facts.assurance.methods === 'unknown' ? 'unknown' : [...facts.assurance.methods],
            mfa: facts.assurance.mfa,
          },
        }),
    ...(facts?.actor === undefined ? {} : { actor: copyActor(facts.actor) }),
    ...(facts?.organizationId === undefined ? {} : { organizationId: facts.organizationId }),
  }
}
