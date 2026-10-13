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
 * Default impersonation policy on the users collection (CAP-8b /
 * D5): the admin panel is denied while impersonating. Any builder
 * `access.admin` still decides every non-impersonated request; the
 * fallback mirrors Payload's default of requiring a signed-in user.
 */
function denyAdminWhileImpersonating(existing: AdminAccess | undefined): AdminAccess {
  return async ({ req }) => {
    if (isImpersonating(req)) {
      return false
    }
    if (existing !== undefined) {
      return existing({ req })
    }
    return req.user !== null && req.user !== undefined
  }
}

/** Wrap a collection's access with the admin-panel default above. */
function withImpersonationAdminAccess(access: CollectionConfig['access']): CollectionAccess {
  return { ...access, admin: denyAdminWhileImpersonating(access?.admin) }
}

function rolesField(wired: WiredOptions): SelectField {
  return {
    name: wired.config.map.rolesField,
    type: 'select',
    hasMany: true,
    // Role changes are denied while impersonating (CAP-8b / D5):
    // field access is the surgical deny — an impersonated update can
    // still touch other fields but can never write roles.
    access: {
      create: ({ req }) => !isImpersonating(req),
      update: ({ req }) => !isImpersonating(req),
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

/**
 * Governance writes (phone, suspension) are denied while
 * impersonating, like roles (CAP-8b/D5): an operator acting as a user
 * must not suspend themselves, unsuspend the target, or rewrite the
 * target's linkable phone.
 */
const denyWriteWhileImpersonating = {
  create: ({ req }: { req: Parameters<typeof isImpersonating>[0] }) => !isImpersonating(req),
  update: ({ req }: { req: Parameters<typeof isImpersonating>[0] }) => !isImpersonating(req),
}

function phoneField(wired: WiredOptions): TextField {
  return {
    name: wired.userFields.phoneField,
    type: 'text',
    index: true,
    access: denyWriteWhileImpersonating,
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
    access: denyWriteWhileImpersonating,
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
    access: denyWriteWhileImpersonating,
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
    access: withImpersonationAdminAccess(undefined),
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
          access: withImpersonationAdminAccess(existing.access),
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
