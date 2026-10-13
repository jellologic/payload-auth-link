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
  CollectionAfterChangeHook,
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

/** Wrap a collection's access with the admin-panel default above. */
function withImpersonationAdminAccess(
  access: CollectionConfig['access'],
  wired: WiredOptions
): CollectionAccess {
  return { ...access, admin: denyAdminWhileImpersonating(access?.admin, wired) }
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
    access: withImpersonationAdminAccess(undefined, wired),
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
      rolesField(wired),
      identitiesField(wired),
      phoneField(wired),
      suspendedUntilField(wired),
      suspendReasonField(wired),
    ],
    hooks: {
      beforeValidate: [normalizeUserEmailHook(map)],
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
  const injected = [
    rolesField(wired),
    identitiesField(wired),
    phoneField(wired),
    suspendedUntilField(wired),
    suspendReasonField(wired),
  ]
  for (const field of injected) {
    const collision = existing.fields.find((candidate) => fieldName(candidate) === field.name)
    if (collision) {
      throw new InvalidConfigError(
        `users collection '${slug}' already has a '${field.name}' field; ` +
          `rename it or point the collection map elsewhere`
      )
    }
  }
  const beforeValidate = existing.hooks?.beforeValidate ?? []
  const afterChange = existing.hooks?.afterChange ?? []
  return (collections ?? []).map((collection) =>
    collection.slug === slug
      ? {
          ...existing,
          access: withImpersonationAdminAccess(existing.access, wired),
          auth: withStrategy(existing.auth, strategy),
          fields: [...existing.fields, ...injected],
          hooks: {
            ...existing.hooks,
            beforeValidate: [...beforeValidate, normalizeUserEmailHook(wired.config.map)],
            afterChange: [...afterChange, suspendRevokeHook(wired)],
          },
        }
      : collection
  )
}
