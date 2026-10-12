import { InvalidConfigError } from '@payload-auth-link/core'
import type { ArrayField, AuthStrategy, CollectionConfig, Field, SelectField } from 'payload'
import type { WiredOptions } from './options.js'
import { normalizeUserEmailHook } from './hooks.js'
import { strategyName } from './strategy.js'

function rolesField(wired: WiredOptions): SelectField {
  return {
    name: wired.config.map.rolesField,
    type: 'select',
    hasMany: true,
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
    admin: {
      useAsTitle: map.emailField,
      defaultColumns: [map.emailField, map.rolesField],
      description: 'Users managed by payload-auth-link.',
    },
    auth: {
      disableLocalStrategy: { enableFields: true, optionalPassword: true },
      strategies: [strategy],
    },
    fields: [rolesField(wired), identitiesField(wired)],
    hooks: {
      beforeValidate: [normalizeUserEmailHook(map)],
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
  const injected = [rolesField(wired), identitiesField(wired)]
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
  return (collections ?? []).map((collection) =>
    collection.slug === slug
      ? {
          ...existing,
          auth: withStrategy(existing.auth, strategy),
          fields: [...existing.fields, ...injected],
          hooks: {
            ...existing.hooks,
            beforeValidate: [...beforeValidate, normalizeUserEmailHook(wired.config.map)],
          },
        }
      : collection
  )
}
