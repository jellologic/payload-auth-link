import { isRecord } from '@payload-auth-link/core'
import type { DoctorIssue, UsersFinding } from './types.js'

/**
 * The users collection analysis (issue #52): collisions with the
 * plugin's injected fields, the existing role field and its values,
 * and whether Payload's local strategy is on — the three things that
 * decide whether a payload-auth app's user table can be adopted as-is.
 */

/**
 * The plugin's injected users-collection field names (see
 * `packages/plugin/src/collections.ts`). The `roles` field is special:
 * the plugin ADOPTS a compatible host select instead of throwing, so a
 * host `roles`/`role` field is analyzed as the role field, not
 * reported as a collision.
 */
const injectedFieldNames: ReadonlySet<string> = new Set([
  'identities',
  'phone',
  'suspendedUntil',
  'suspendReason',
  'linkable',
  'linkableEmail',
])

/** Canonical roles are lowercase slugs (`staff`, `front-plugin`). */
const canonicalRole = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/

/** Narrow a config field list; configs are untyped at this boundary. */
function fieldList(collection: Record<string, unknown>): Record<string, unknown>[] {
  const fields: unknown = collection.fields
  if (!Array.isArray(fields)) {
    return []
  }
  return fields.filter(isRecord)
}

function fieldName(field: Record<string, unknown>): string | null {
  return typeof field.name === 'string' && field.name !== '' ? field.name : null
}

function fieldType(field: Record<string, unknown>): string {
  return typeof field.type === 'string' ? field.type : 'unknown'
}

function selectValues(field: Record<string, unknown>): string[] {
  const options: unknown = field.options
  if (!Array.isArray(options)) {
    return []
  }
  return options
    .map((option) => (typeof option === 'string' ? option : isRecord(option) ? option.value : null))
    .filter((value): value is string => typeof value === 'string')
}

/** Find the payload-auth-shaped users collection (or the app's own users slug). */
export function findUsersCollection(
  config: unknown,
  usersSlug: string
): Record<string, unknown> | null {
  if (!isRecord(config) || !Array.isArray(config.collections)) {
    return null
  }
  for (const collection of config.collections) {
    if (isRecord(collection) && collection.slug === usersSlug) {
      return collection
    }
  }
  return null
}

/** Names of the custom auth strategies a collection declares. */
function strategiesOf(collection: Record<string, unknown>): string[] {
  const auth: unknown = collection.auth
  if (!isRecord(auth) || !Array.isArray(auth.strategies)) {
    return []
  }
  return auth.strategies
    .filter(isRecord)
    .map((strategy) => strategy.name)
    .filter((name): name is string => typeof name === 'string')
}

/**
 * Payload's local email+password strategy for a collection, as the
 * BUILT config has it. payload-auth leaves it on unless the app set
 * `disableDefaultPayloadAuth: true`; either way, this reads the result.
 */
export function localStrategyOn(collection: Record<string, unknown>): boolean {
  const auth: unknown = collection.auth
  if (auth === undefined || auth === null) {
    return false
  }
  if (auth === true) {
    return true
  }
  return isRecord(auth) ? auth.disableLocalStrategy !== true : false
}

/**
 * The payload-auth-link plugin's own auth strategy name
 * (`packages/plugin/src/strategy.ts`). A users collection carrying it
 * has ALREADY been through `authLink` — its identities/linkable/…
 * fields are the plugin's own injections, not host collisions
 * (issue #88: the doctor run against the TARGET config).
 */
const pluginStrategyName = 'auth-link'

export function analyzeUsersCollection(
  collection: Record<string, unknown> | null,
  rolesFieldName: string,
  options: {
    /**
     * The config is an adopt-mode TARGET: payload-auth-link is installed
     * and Better Auth serves its users from this collection (no ba-users
     * collection). Enables the target-side adopt checks.
     */
    readonly adoptTarget?: boolean | undefined
  } = {}
): { finding: UsersFinding | null; issues: DoctorIssue[] } {
  if (collection === null) {
    return {
      finding: null,
      issues: [
        { code: 'users-collection-missing', detail: 'no users collection found in the config' },
      ],
    }
  }
  const fields = fieldList(collection)
  const issues: DoctorIssue[] = []
  const notes: string[] = []

  // On the target config the plugin already injected these fields:
  // they are its own, never a collision (issue #88).
  const pluginInstalled = strategiesOf(collection).includes(pluginStrategyName)
  const collisions = pluginInstalled
    ? []
    : fields
        .map(fieldName)
        .filter((name): name is string => name !== null)
        .filter((name) => injectedFieldNames.has(name))
  if (pluginInstalled) {
    notes.push(
      'payload-auth-link is already installed on this collection (its auth-link strategy is present): the injected fields are the plugin’s own'
    )
  }

  let roleField: UsersFinding['roleField'] = null
  const roleCandidates = fields.filter((field) => {
    const name = fieldName(field)
    return name === rolesFieldName || name === 'role'
  })
  for (const field of roleCandidates) {
    const name = fieldName(field) ?? 'role'
    if (fieldType(field) === 'select') {
      const values = selectValues(field)
      const nonCanonical = values.filter((value) => !canonicalRole.test(value))
      roleField = {
        name,
        type: fieldType(field),
        hasMany: field.hasMany === true,
        values,
        nonCanonical,
      }
      if (nonCanonical.length > 0) {
        issues.push({
          code: 'non-canonical-role-value',
          detail: `the '${name}' field stores non-canonical value(s) ${nonCanonical
            .map((value) => `'${value}'`)
            .join(
              ', '
            )}; the role value map (#56) keeps them stored as-is while roles stay canonical inside the plugin`,
        })
      }
      if (field.hasMany !== true) {
        issues.push({
          code: 'roles-field-single-select',
          detail: `the '${name}' field is a single-select; the plugin can only adopt a multi-select (hasMany) covering every configured role`,
        })
      }
    } else if (name === rolesFieldName) {
      issues.push({
        code: 'roles-field-not-select',
        detail: `the '${rolesFieldName}' field is a '${fieldType(field)}', not a select; rename it and let the plugin inject its governed field`,
      })
    }
  }

  if (collisions.length > 0) {
    issues.push({
      code: 'injected-field-collision',
      detail: `field(s) ${collisions
        .map((name) => `'${name}'`)
        .join(
          ', '
        )} collide with the plugin's injected fields; rename them before booting payload-auth-link (its config throws on collisions)`,
    })
  }

  const local = localStrategyOn(collection)
  if (local) {
    notes.push(
      'Payload local strategy is ON for this collection: since 0.7.0, provider-linked documents refuse local sign-in and forgot/reset by default — break-glass operator accounts keep theirs; allowLocalCredentialsForLinkedDocs: true reopens it only for a migration window'
    )
    if (options.adoptTarget === true) {
      // Adopt mode (issue #110): Better Auth creates its users IN this
      // collection, and Payload's local strategy demands a password on
      // every create — sign-up and anonymous sign-in fail for every
      // new user.
      issues.push({
        code: 'adopt-local-strategy-on',
        detail: `adopt mode serves Better Auth's users from the collection '${typeof collection.slug === 'string' ? collection.slug : 'users'}', but Payload's local strategy is ON there: Payload requires a password on every create, so every NEW user fails (email sign-up 422, anonymous sign-in 500 "field is invalid: password"). Set auth: { disableLocalStrategy: true } on the collection (payload-auth's disableDefaultPayloadAuth: true did the same), or use the importer (ba-* collections) instead of adopt`,
      })
    }
  } else {
    const strategies = Array.isArray(collection.auth) ? [] : strategiesOf(collection)
    notes.push(
      strategies.length > 0
        ? `Payload local strategy is OFF; authentication rides custom strategy/ies: ${strategies.join(', ')}`
        : 'Payload local strategy is OFF for this collection'
    )
  }
  if (isRecord(collection.auth) && collection.auth.useAPIKey === true) {
    notes.push(
      'useAPIKey is enabled: API keys are refused for suspended users at request time since 0.7.0 and never carry MFA-gated roles'
    )
  }

  return {
    finding: {
      slug: typeof collection.slug === 'string' ? collection.slug : 'users',
      roleField,
      localStrategy: local,
      collisions,
      notes,
    },
    issues,
  }
}

export function injectedFieldNamesForDocs(): readonly string[] {
  return [...injectedFieldNames, 'roles', 'email']
}
