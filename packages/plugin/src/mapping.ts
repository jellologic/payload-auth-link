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
  /**
   * Stored value → canonical role (issue #56). Present when the site
   * maps role values; reads translate through it before validation, so
   * a payload-auth layout keeps storing e.g. `frontPlugin` while the
   * plugin reasons about `front-plugin`.
   */
  readonly roleValuesReverse?: Readonly<Record<string, string>> | undefined
  /**
   * Canonical role → stored value (issue #56); present for writes.
   * Unmapped roles store their canonical form, so this is total when
   * present.
   */
  readonly roleValues?: Readonly<Record<string, string>> | undefined
  /**
   * Roles the site currently configures (B11 role-config safety).
   * When present, stored roles outside this set are dropped at read
   * time — a removed role must stop granting access at the very next
   * session, not after some future user-doc write happens to rewrite
   * the column. The plugin always passes it; direct mapping callers
   * may omit it to keep the format-only narrowing.
   */
  readonly configuredRoles?: ReadonlySet<Role> | undefined
}

const defaultUserFields = {
  phoneField: 'phone',
  suspendedUntilField: 'suspendedUntil',
  suspendReasonField: 'suspendReason',
} as const

// Stored-row degradation warnings aggregate once per message per
// logger (B20): a corrupt column on ten thousand rows is one alert
// an operator can act on, not ten thousand lines that train them to
// ignore the log. Keyed by logger instance so each composition root
// (and each test) gets its own first warning.
const warnedByLogger = new WeakMap<LoggerPort, Set<string>>()

function warnOnce(ctx: MappingContext, message: string): void {
  let warned = warnedByLogger.get(ctx.logger)
  if (warned === undefined) {
    warned = new Set<string>()
    warnedByLogger.set(ctx.logger, warned)
  }
  if (warned.has(message)) {
    return
  }
  warned.add(message)
  ctx.logger.warn(message)
}

function toIdentityRow(row: unknown, email: string, ctx: MappingContext): LinkedIdentity | null {
  if (!isRecord(row)) {
    warnOnce(ctx, 'dropping malformed identity row: not an object')
    return null
  }
  const providerId = providerIdSchema.safeParse(row.providerId)
  if (!providerId.success) {
    warnOnce(ctx, 'dropping identity row: invalid providerId')
    return null
  }
  if (typeof row.providerUserId !== 'string' || row.providerUserId === '') {
    warnOnce(ctx, 'dropping identity row: invalid providerUserId')
    return null
  }
  const parsedEmail = parseEmail(row.email ?? email)
  if (parsedEmail.isErr()) {
    warnOnce(ctx, 'dropping identity row: invalid email')
    return null
  }
  const linkedAt = toDate(row.linkedAt)
  if (!linkedAt) {
    warnOnce(ctx, 'dropping identity row: invalid linkedAt')
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
 *
 * With `configuredRoles` (B11), stored roles outside the configured
 * set are dropped here, so removing a role from `authLink({ roles })`
 * stops granting it on the next session — with one warning per
 * removed role, so the operator learns which stored values drifted.
 */
function toRoles(value: unknown, ctx: MappingContext): readonly Role[] | null {
  if (value === undefined) {
    return [ctx.defaultRole]
  }
  if (!Array.isArray(value)) {
    warnOnce(ctx, 'cannot map user doc: roles field is not an array')
    return null
  }
  const roles: Role[] = []
  for (const entry of value) {
    // Storage edge (issue #56): translate the stored value to its
    // canonical role before validating.
    const canonical: unknown =
      ctx.roleValuesReverse === undefined ? entry : (ctx.roleValuesReverse[String(entry)] ?? entry)
    const parsed = parseRole(canonical)
    if (parsed.isErr()) {
      warnOnce(ctx, 'dropping invalid role entry')
      continue
    }
    if (ctx.configuredRoles !== undefined && !ctx.configuredRoles.has(parsed.value)) {
      warnOnce(ctx, `dropping role '${parsed.value}': not in the configured roles set`)
      continue
    }
    roles.push(parsed.value)
  }
  if (roles.length === 0) {
    warnOnce(ctx, 'cannot map user doc: no valid roles')
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
    warnOnce(ctx, 'cannot map user doc: not an object')
    return null
  }
  const rawId = doc.id
  if ((typeof rawId !== 'string' && typeof rawId !== 'number') || rawId === '') {
    warnOnce(ctx, 'cannot map user doc: invalid id')
    return null
  }
  const email = parseEmail(doc[ctx.map.emailField])
  if (email.isErr()) {
    warnOnce(ctx, 'cannot map user doc: invalid email')
    return null
  }
  const createdAt = toDate(doc.createdAt)
  const updatedAt = toDate(doc.updatedAt)
  if (!createdAt || !updatedAt) {
    warnOnce(ctx, 'cannot map user doc: invalid timestamps')
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
      warnOnce(ctx, 'identities field is not an array; treating as empty')
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
      warnOnce(ctx, 'dropping invalid stored phone value')
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
      warnOnce(ctx, 'cannot map user doc: invalid suspendedUntil')
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
    warnOnce(ctx, 'cannot map find result: missing docs array')
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
  ctx: Pick<MappingContext, 'map' | 'clock' | 'userFields' | 'roleValues'>,
  password: string
): Record<string, unknown> {
  const phoneField = (ctx.userFields ?? defaultUserFields).phoneField
  return {
    [ctx.map.emailField]: input.email,
    password,
    // Storage edge (issue #56): canonical roles go in as their stored
    // values.
    [ctx.map.rolesField]: input.roles.map((role) => ctx.roleValues?.[role] ?? role),
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
