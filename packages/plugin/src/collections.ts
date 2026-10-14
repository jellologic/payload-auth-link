import {
  InvalidConfigError,
  isRecord,
  isSuspendedAt,
  parsePhoneNumber,
  toDate,
} from '@payload-auth-link/core'
import type {
  ArrayField,
  AuthStrategy,
  CheckboxField,
  CollectionAfterChangeHook,
  CollectionBeforeChangeHook,
  CollectionConfig,
  DateField,
  Field,
  FieldAccess,
  FieldAccessArgs,
  SelectField,
  TextField,
} from 'payload'
import { isImpersonating } from './access.js'
import type { WiredOptions } from './options.js'
import { normalizeUserEmailHook } from './hooks.js'
import { strategyName } from './strategy.js'

type CollectionAccess = NonNullable<CollectionConfig['access']>
type AdminAccess = NonNullable<CollectionAccess['admin']>

/**
 * Roles on the request's user (the session projection or a full
 * Payload user document); empty when there is no usable shape.
 */
function userRoles(user: unknown): readonly string[] {
  if (!isRecord(user)) {
    return []
  }
  const roles = user.roles
  if (!Array.isArray(roles)) {
    return []
  }
  return roles.filter((role): role is string => typeof role === 'string')
}

/**
 * May this request govern the auth system — write roles/governance
 * fields, read operator-facing fields, reach the admin panel by
 * default? Fails closed: no user, no roles
 * array, or no intersection with the configured manager roles means
 * no.
 */
function isRoleManager(req: FieldAccessArgs['req'], wired: WiredOptions): boolean {
  const managers = new Set<string>(wired.roleManagerRoles)
  return userRoles(req.user).some((role) => managers.has(role))
}

/** Is this request reading/writing its own user document? */
function isSelfDoc(req: FieldAccessArgs['req'], id: FieldAccessArgs['id']): boolean {
  const user = req.user
  return isRecord(user) && id !== undefined && String(user.id) === String(id)
}

/**
 * Default impersonation policy on the users collection (CAP-8b /
 * D5): the admin panel is denied while impersonating. A builder
 * `access.admin` still decides every non-impersonated request; the
 * fallback is the role-manager roles — never "any signed-in user",
 * which made every linked user an admin-panel user
 *.
 */
function denyAdminWhileImpersonating(
  existing: AdminAccess | undefined,
  wired: WiredOptions
): AdminAccess {
  return async ({ req }) => {
    if (isImpersonating(req)) {
      return false
    }
    if (existing !== undefined) {
      return existing({ req })
    }
    return isRoleManager(req, wired)
  }
}

/**
 * Governance writes (roles, phone, suspension) on injected fields:
 * role-manager roles only, with the impersonation deny on top. The
 * Local API (overrideAccess) never runs field access, so the
 * plugin's own engine-driven writes are unaffected.
 * (security hardening: Payload's field-access default allowed any
 * authenticated user to write roles — a self-service privilege
 * escalation.)
 */
function governedWrite(wired: WiredOptions): { create: FieldAccess; update: FieldAccess } {
  const decide = ({ req }: FieldAccessArgs) => !isImpersonating(req) && isRoleManager(req, wired)
  return { create: decide, update: decide }
}

/** Read access: role managers, or the document's own user. */
function readSelfOrManagers(wired: WiredOptions): FieldAccess {
  return ({ req, id }) => isRoleManager(req, wired) || isSelfDoc(req, id)
}

/** Read access: role managers only (operator-facing data). */
function readManagersOnly(wired: WiredOptions): FieldAccess {
  return ({ req }) => isRoleManager(req, wired)
}

/**
 * `req.context` key the plugin sets on engine-driven Local-API creates
 * (JIT provisioning, credentials registration): proof the document was
 * created by payload-auth-link itself, from a verified provider
 * identity.
 */
export const linkableCreateMarker = 'payload-auth-link:create'

/**
 * Fill collection-level `create`/`read` defaults on the users
 * collection (GHSA-98hq-hh6v-2p2r): Payload's own defaults give every
 * authenticated user create and list access to every user document,
 * which enabled pre-account hijack through JIT email linking and user
 * enumeration. Gaps are filled per key; a host-declared function is
 * never overridden.
 */
function withDefaultUserAccess(
  access: CollectionConfig['access'],
  wired: WiredOptions
): CollectionAccess {
  const filled: CollectionAccess = { ...access }
  if (filled.create === undefined) {
    const decide = ({ req }: { req: Parameters<typeof isImpersonating>[0] }) =>
      !isImpersonating(req) && isRoleManager(req, wired)
    filled.create = decide
  }
  if (filled.read === undefined) {
    // Managers see every user; everyone else is constrained to their
    // own document (list and find alike) — user enumeration was the
    // targeting step of the pre-account hijack.
    filled.read = ({ req }) => {
      if (isRoleManager(req, wired)) {
        return true
      }
      const user = req.user
      if (isRecord(user) && typeof user.email === 'string' && user.email !== '') {
        return { [wired.config.map.emailField]: { equals: user.email } }
      }
      return false
    }
  }
  filled.admin = denyAdminWhileImpersonating(filled.admin, wired)
  return filled
}

/**
 * The JIT-linking proof marker (GHSA-98hq-hh6v-2p2r): a document is
 * linked by email only when something has proven it owns that email.
 * The plugin sets the marker on engine-driven creates (verified
 * provider identity) and on role-manager creates (admin/import
 * workflows); documents created any other way — or created outside
 * the plugin — start unproven and are never JIT-linked until a role
 * manager marks them. Plain-user creates are refused at the
 * collection level, so the flag cannot be self-granted.
 */
function linkableMarkerHook(wired: WiredOptions): CollectionBeforeChangeHook {
  return ({ operation, data, req }) => {
    if (operation !== 'create') {
      return
    }
    const proven =
      isRoleManager(req, wired) ||
      (isRecord(req.context) && req.context[linkableCreateMarker] === true)
    if (proven) {
      data.linkable = true
      // Proof is bound to the email: an email change that is not the
      // plugin's own provider-email sync invalidates it automatically
      // (the guard compares the two on every lookup).
      if (typeof data.email === 'string' && data.email !== '') {
        data.linkableEmail = data.email
      }
    } else if (data.linkable === undefined) {
      data.linkable = false
    }
  }
}

function linkableField(wired: WiredOptions): CheckboxField {
  return {
    name: 'linkable',
    type: 'checkbox',
    defaultValue: false,
    // The JIT-linking proof: writing it is a role-manager decision
    // (it grants linking to whatever email the document carries);
    // users never read it.
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description:
        'Set when payload-auth-link (or a role manager) proved this document owns its email. JIT linking refuses documents without it.',
    },
  }
}

/**
 * The email the `linkable` proof was granted for (GHSA-8524). The
 * proof holds only while the document's email still equals it — a
 * self-service email change therefore invalidates linking until a
 * role manager re-proves the new address. The plugin's own
 * provider-email resync keeps the proof in step (repository
 * `setEmail`).
 */
function linkableEmailField(wired: WiredOptions): TextField {
  return {
    name: 'linkableEmail',
    type: 'text',
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description:
        'The email the linkable proof was granted for. JIT linking requires it to match the document email.',
    },
  }
}

/**
 * Email changes over REST on documents with linked identities are
 * role-manager-only (GHSA-8524): a self-service email change on a
 * linked document would move a proven, linkable identity surface onto
 * an unverified address. Documents without linked identities are the
 * owner's to rename (nothing links to them by email yet). The
 * plugin's provider-email resync runs with `overrideAccess` and is
 * unaffected.
 */
function emailUpdateAccess(wired: WiredOptions): FieldAccess {
  return ({ req, doc }) => {
    if (isImpersonating(req)) {
      return false
    }
    if (isRoleManager(req, wired)) {
      return true
    }
    const identities = isRecord(doc) ? doc[wired.config.map.identitiesField] : undefined
    const hasIdentities = Array.isArray(identities) && identities.length > 0
    return !hasIdentities
  }
}

/**
 * Self-service local passwords are fail-closed (GHSA-8524): a
 * provider-provisioned user must not be able to mint a Payload local
 * credential for their document, which would bypass Better Auth's
 * MFA, bans, rate limits, and verification. Non-manager password
 * writes are stripped in beforeOperation (before Payload's update
 * reads `data.password`); role managers may set passwords, and hosts
 * who declare their own password field access keep it.
 */
function passwordGuardHook(
  wired: WiredOptions
): NonNullable<CollectionConfig['hooks']>['beforeOperation'] extends (infer F)[] | undefined
  ? F
  : never {
  return ({ args, operation, req }) => {
    if (operation !== 'update') {
      return args
    }
    const data = isRecord(args) ? args.data : undefined
    if (!isRecord(data) || data.password === undefined) {
      return args
    }
    if (isImpersonating(req) || !isRoleManager(req, wired)) {
      const stripped = { ...data }
      delete stripped.password
      return { ...args, data: stripped }
    }
    return args
  }
}

function emailField(wired: WiredOptions): Field {
  return {
    name: wired.config.map.emailField,
    type: 'email',
    access: { update: emailUpdateAccess(wired) },
  }
}

function rolesField(wired: WiredOptions): SelectField {
  return {
    name: wired.config.map.rolesField,
    type: 'select',
    hasMany: true,
    // Role changes are denied while impersonating (CAP-8b / D5) and
    // restricted to the role-manager roles:
    // field access is the surgical deny — an impersonated update can
    // still touch other fields but can never write roles, and a
    // plain user can never write roles at all. Users still read
    // their own roles (the session projection carries them anyway).
    access: {
      ...governedWrite(wired),
      read: readSelfOrManagers(wired),
    },
    // Required rejects `[]` for hasMany selects (Payload's select
    // validation treats an empty array as missing), so emptied roles
    // can no longer persist through the API or admin UI.
    required: true,
    options: wired.config.roles.map((role) => ({ label: role, value: role })),
    defaultValue: [wired.config.defaultRole],
    admin: {
      description: 'Managed by payload-auth-link. At least one role is required.',
    },
  }
}

function identitiesField(wired: WiredOptions): ArrayField {
  return {
    name: wired.config.map.identitiesField,
    type: 'array',
    // Engine-managed data: writes are denied at
    // field level for every REST/admin caller — linking happens
    // through the plugin's Local-API paths only — and reads are
    // role-manager only: identity rows carry provider user ids and
    // emails that are not the reader's to enumerate.
    access: {
      create: () => false,
      update: () => false,
      read: readManagersOnly(wired),
    },
    admin: {
      readOnly: true,
      description: 'Provider identities linked by payload-auth-link. Managed automatically.',
      components: {
        RowLabel: {
          path: '@payload-auth-link/plugin/admin',
          exportName: 'IdentityRowLabel',
        },
      },
    },
    fields: [
      { name: 'providerId', type: 'text', required: true },
      { name: 'providerUserId', type: 'text', required: true },
      { name: 'email', type: 'email', required: true },
      { name: 'linkedAt', type: 'date', required: true },
    ],
  }
}

function phoneField(wired: WiredOptions): TextField {
  return {
    name: wired.userFields.phoneField,
    type: 'text',
    index: true,
    // A phone value is a linking identifier (CAP-9): if users could
    // write it, they could aim a verified-phone claim at an account
    // they do not own, so writes are role-manager only, like the
    // other governance fields. Claim-driven
    // writes flow through the Local API and are unaffected.
    access: { ...governedWrite(wired), read: readSelfOrManagers(wired) },
    // E.164 only: this value is a linking identifier (CAP-9), not a
    // display string. Empty clears it.
    validate: (value: unknown) => {
      if (value === undefined || value === null || value === '') {
        return true
      }
      const parsed = parsePhoneNumber(value)
      return parsed.isOk() ? true : parsed.error.message
    },
    admin: {
      description:
        'Verified E.164 phone (e.g. +14155550132). Synced from a verified provider phone claim; used only to link phone sign-ins to this existing user.',
    },
  }
}

function suspendedUntilField(wired: WiredOptions): DateField {
  return {
    name: wired.userFields.suspendedUntilField,
    type: 'date',
    index: true,
    // Governance write + operator-facing read:
    // whether a user is suspended and until when is not their read.
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description:
        'Suspended until this instant (payload-auth-link CAP-7). While in the future, every provider session for this user is refused; clear it or let it lapse to readmit.',
      date: { pickerAppearance: 'dayAndTime' },
    },
  }
}

function suspendReasonField(wired: WiredOptions): TextField {
  return {
    name: wired.userFields.suspendReasonField,
    type: 'text',
    // Operator-facing: never exposed to the
    // user or clients, matching the docs — managers read, managers
    // write, and the deny-while-impersonating rule stays on top.
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description: 'Operator-facing suspension reason. Never exposed to the user or clients.',
    },
  }
}

/**
 * Best-effort provider revocation on suspension (CAP-7): when a write
 * puts `suspendedUntil` into the future (and it was not already
 * there), every linked identity's provider sessions are revoked via
 * `revokeUserSessions` where the adapter supports it. Failures are
 * logged, never thrown — the Payload-side verify gate refuses the
 * user regardless, so revocation is defense in depth, and a provider
 * outage must not roll back an operator's suspension.
 */
function suspendRevokeHook(wired: WiredOptions): CollectionAfterChangeHook {
  return async ({ doc, previousDoc }) => {
    const field = wired.userFields.suspendedUntilField
    const now = wired.clock.now()
    const next = isRecord(doc) ? toDate(doc[field]) : null
    if (!isSuspendedAt(next, now)) {
      return
    }
    const prev = isRecord(previousDoc) ? toDate(previousDoc[field]) : null
    if (prev !== null && next !== null && prev.getTime() === next.getTime()) {
      return
    }
    const identities: unknown = isRecord(doc) ? doc[wired.config.map.identitiesField] : undefined
    if (Array.isArray(identities)) {
      for (const row of identities) {
        if (!isRecord(row)) {
          continue
        }
        const { providerId, providerUserId } = row
        if (typeof providerId !== 'string' || typeof providerUserId !== 'string') {
          continue
        }
        const parsedId =
          typeof providerId === 'string'
            ? wired.registry.ids().find((id) => id === providerId)
            : undefined
        if (parsedId === undefined) {
          continue
        }
        const required = wired.registry.require(parsedId)
        if (required.isErr() || required.value.revokeUserSessions === undefined) {
          continue
        }
        const revoked = await required.value.revokeUserSessions(providerUserId)
        if (revoked.isErr()) {
          wired.logger.error('suspend: provider session revoke failed', {
            providerId,
            cause: revoked.error.cause ?? revoked.error,
          })
        } else {
          wired.logger.info('suspend: provider sessions revoked', { providerId })
        }
      }
    }
    // No return: the hook never modifies the document.
  }
}

/** Field name when the field variant has one (`collapsible` has none). */
export function fieldName(field: Field): string | undefined {
  return 'name' in field ? field.name : undefined
}

function withStrategy(
  auth: CollectionConfig['auth'],
  strategy: AuthStrategy
): Exclude<CollectionConfig['auth'], undefined> {
  if (auth === undefined || auth === false) {
    return { strategies: [strategy] }
  }
  if (auth === true) {
    return { strategies: [strategy] }
  }
  const strategies = auth.strategies ?? []
  if (strategies.some((candidate) => candidate.name === strategyName)) {
    return auth
  }
  return { ...auth, strategies: [...strategies, strategy] }
}

function createUsersCollection(wired: WiredOptions, strategy: AuthStrategy): CollectionConfig {
  const { map } = wired.config
  return {
    slug: map.usersCollection,
    access: withDefaultUserAccess(undefined, wired),
    admin: {
      useAsTitle: map.emailField,
      defaultColumns: [map.emailField, map.rolesField],
      description: 'Users managed by payload-auth-link.',
    },
    auth: {
      disableLocalStrategy: { enableFields: true, optionalPassword: true },
      strategies: [strategy],
    },
    fields: [
      emailField(wired),
      rolesField(wired),
      identitiesField(wired),
      phoneField(wired),
      suspendedUntilField(wired),
      suspendReasonField(wired),
      linkableField(wired),
      linkableEmailField(wired),
    ],
    hooks: {
      beforeValidate: [normalizeUserEmailHook(map)],
      beforeOperation: [passwordGuardHook(wired)],
      beforeChange: [linkableMarkerHook(wired)],
      afterChange: [suspendRevokeHook(wired)],
    },
  }
}

/**
 * Ensure the users collection exists with our fields, strategy, and hooks.
 * Pure config transform: never mutates its input, never overwrites existing
 * hooks or strategies, and throws {@link InvalidConfigError} on field-name
 * collisions instead of silently skipping them.
 */
/**
 * Adopt a compatible host `roles` field instead of throwing (a
 * migration path from plugins that made the Payload user table BE the
 * provider's user table — those apps already carry a role select).
 * Compatible means: Payload `select`, `hasMany: true`, and an options
 * list that covers every configured role (extra options are the
 * host's business and stay). Adoption imposes the plugin's
 * governance — required, role-manager write access, self/manager
 * read, the default — and leaves the host's options, labels, and
 * admin presentation untouched.
 */
function adoptRolesField(host: Field, wired: WiredOptions): SelectField {
  const slug = wired.config.map.usersCollection
  const name = wired.config.map.rolesField
  const fail = (detail: string): never => {
    throw new InvalidConfigError(
      `users collection '${slug}' has a '${name}' field this plugin cannot adopt: ${detail} ` +
        `Make it a multi-select covering every configured role, or rename it and let ` +
        `the plugin inject '${name}'.`
    )
  }
  if (host.type !== 'select') {
    fail(`it is a '${host.type}' field, not a select`)
  }
  const select = host as SelectField
  if (select.hasMany !== true) {
    fail('it is a single-select (hasMany is not true)')
  }
  const configured = new Set<string>(wired.config.roles)
  const declared = new Set<string>(
    (select.options ?? [])
      .map((option) => (typeof option === 'string' ? option : option.value))
      .filter((value): value is string => typeof value === 'string')
  )
  const missing = [...configured].filter((role) => !declared.has(role))
  if (missing.length > 0) {
    fail(
      `its options are missing the configured role(s) ${missing.map((r) => `'${r}'`).join(', ')}`
    )
  }
  return {
    ...select,
    access: { ...governedWrite(wired), read: readSelfOrManagers(wired) },
    required: true,
    ...(select.defaultValue === undefined ? { defaultValue: [wired.config.defaultRole] } : {}),
  }
}

export function applyUsersCollection(
  collections: readonly CollectionConfig[] | undefined,
  wired: WiredOptions,
  strategy: AuthStrategy
): CollectionConfig[] {
  const slug = wired.config.map.usersCollection
  const existing = collections?.find((collection) => collection.slug === slug)
  if (!existing) {
    return [...(collections ?? []), createUsersCollection(wired, strategy)]
  }
  const rolesName = wired.config.map.rolesField
  const hostRolesField = existing.fields.find((candidate) => fieldName(candidate) === rolesName)
  // An existing roles-shaped select is ADOPTED (migration from
  // plugins whose users table carried the role column); anything else
  // colliding with the plugin's names still fails fast with the
  // remediation.
  const roles: Field =
    hostRolesField === undefined ? rolesField(wired) : adoptRolesField(hostRolesField, wired)
  const identities = identitiesField(wired)
  const governance = [
    phoneField(wired),
    suspendedUntilField(wired),
    suspendReasonField(wired),
    linkableField(wired),
    linkableEmailField(wired),
  ]
  // Email gap-fill (GHSA-8524): when the host's users collection has
  // no email field in its config (Payload injects the base field at
  // sanitize time), the plugin injects one carrying the fail-closed
  // update access; when the host declares one, its access wins and
  // only an absent update access is gap-filled.
  const hostEmailField = existing.fields.find(
    (candidate) => fieldName(candidate) === wired.config.map.emailField
  )
  let email: Field
  if (hostEmailField === undefined) {
    email = emailField(wired)
  } else if (
    isRecord((hostEmailField as { access?: Record<string, unknown> }).access) &&
    (hostEmailField as { access?: Record<string, unknown> }).access?.update !== undefined
  ) {
    email = hostEmailField
  } else {
    // Deep-merge at sanitize keeps the base email field's required/
    // hooks; only the access here is ours. The union spread needs the
    // narrow cast back to the field type.
    email = {
      ...hostEmailField,
      access: { update: emailUpdateAccess(wired) },
    } as typeof hostEmailField
  }
  for (const field of [identities, ...governance]) {
    const collision = existing.fields.find((candidate) => fieldName(candidate) === field.name)
    if (collision) {
      const remediation =
        field.name === wired.config.map.identitiesField
          ? 'rename it or point the collection map elsewhere (the identities array is engine-managed and cannot be adopted)'
          : 'rename it or point the collection map elsewhere'
      throw new InvalidConfigError(
        `users collection '${slug}' already has a '${field.name}' field; ${remediation}`
      )
    }
  }
  const beforeValidate = existing.hooks?.beforeValidate ?? []
  const afterChange = existing.hooks?.afterChange ?? []
  // Replace the host's roles/email fields in place when present (the
  // adopted/governed variants); append whatever is missing. Payload
  // rejects duplicate field names, so injection must never follow a
  // failed replacement.
  const replaced = existing.fields.map((field) =>
    field === hostRolesField ? roles : field === hostEmailField ? email : field
  )
  const fields = [
    ...replaced,
    ...(hostRolesField === undefined ? [roles] : []),
    ...(hostEmailField === undefined ? [email] : []),
    identities,
    ...governance,
  ]
  return (collections ?? []).map((collection) =>
    collection.slug === slug
      ? {
          ...existing,
          access: withDefaultUserAccess(existing.access, wired),
          auth: withStrategy(existing.auth, strategy),
          fields,
          hooks: {
            ...existing.hooks,
            beforeValidate: [...beforeValidate, normalizeUserEmailHook(wired.config.map)],
            beforeOperation: [...(existing.hooks?.beforeOperation ?? []), passwordGuardHook(wired)],
            beforeChange: [...(existing.hooks?.beforeChange ?? []), linkableMarkerHook(wired)],
            afterChange: [...afterChange, suspendRevokeHook(wired)],
          },
        }
      : collection
  )
}
