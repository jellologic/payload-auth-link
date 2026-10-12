import {
  assertUniqueSlugs,
  denyAllAccess,
  InvalidConfigError,
  resolveSlugs,
} from '@payload-auth-link/core'
import type { CollectionConfig, Field } from 'payload'

/** Access control for the Better Auth system collections. */
export type BetterAuthCollectionsAccess = NonNullable<CollectionConfig['access']>

/** Canonical Better Auth models persisted in Payload. */
export type BetterAuthModelKey = 'user' | 'session' | 'account' | 'verification' | 'rateLimit'

/** Payload collection slugs backing each Better Auth model. */
export type BetterAuthCollectionSlugs = Record<BetterAuthModelKey, string>

/** Default `ba-*` slugs; override per model via options. */
export const defaultBetterAuthSlugs: BetterAuthCollectionSlugs = {
  user: 'ba-users',
  session: 'ba-sessions',
  account: 'ba-accounts',
  verification: 'ba-verifications',
  rateLimit: 'ba-rate-limits',
}

/** Payload column types a custom field can map to. */
export type BetterAuthCustomFieldType = 'text' | 'number' | 'boolean' | 'date' | 'json'

/**
 * A builder-declared custom field: an `additionalFields` entry (or plugin
 * field) on a core model, or a field of a custom model. The declaration
 * must match Better Auth's schema exactly — the adapter fail-fasts both
 * undeclared schema fields and declared-but-absent names.
 */
export type BetterAuthCustomField = {
  readonly name: string
  /** Payload column type; match Better Auth's attribute type. */
  readonly type: BetterAuthCustomFieldType
  readonly required?: boolean | undefined
  /** Unique + indexed (text/number/date only). */
  readonly unique?: boolean | undefined
}

/**
 * A builder-declared custom model: a plugin model (e.g. the organization
 * plugin's `organization`, `member`, `invitation`) the adapter should
 * serve. Gets its own `ba-*` collection with a `baId` id column.
 */
export type BetterAuthCustomModel = {
  /** Better Auth model name, exactly as the plugin registers it. */
  readonly model: string
  /** Collection slug. Defaults to `ba-${model}`. */
  readonly slug?: string | undefined
  /** Admin label. Defaults to `Better Auth ${model}`. */
  readonly label?: string | undefined
  readonly fields: readonly BetterAuthCustomField[]
}

/** Slug overrides and access for {@link createBetterAuthCollections}. */
export type BetterAuthCollectionsOptions = {
  /** Override any default slug. Unmentioned models keep their defaults. */
  readonly slugs?: Partial<BetterAuthCollectionSlugs> | undefined
  /**
   * Access control for the system collections. Defaults to deny-all: these
   * tables hold credential material (hashes, tokens) and the adapter writes
   * with `overrideAccess`, so no API access is needed. Builders may open
   * `read` for operations debugging.
   */
  readonly access?: BetterAuthCollectionsAccess | undefined
  /** Custom fields appended to core-model collections. */
  readonly customFields?:
    Partial<Record<BetterAuthModelKey, readonly BetterAuthCustomField[]>> | undefined
  /** Custom plugin-model collections. */
  readonly customModels?: readonly BetterAuthCustomModel[] | undefined
}

/**
 * Canonical Better Auth core fields per model (mirrors `get-tables`; `id`
 * is implicit). Single source of truth shared by the collections (which
 * must not collide with it) and the adapter (which allowlists it).
 */
export const betterAuthCoreFields: Record<BetterAuthModelKey, readonly string[]> = {
  user: ['name', 'email', 'emailVerified', 'image', 'createdAt', 'updatedAt'],
  session: ['expiresAt', 'token', 'createdAt', 'updatedAt', 'ipAddress', 'userAgent', 'userId'],
  account: [
    'accountId',
    'providerId',
    'userId',
    'accessToken',
    'refreshToken',
    'idToken',
    'accessTokenExpiresAt',
    'refreshTokenExpiresAt',
    'scope',
    'password',
    'createdAt',
    'updatedAt',
  ],
  verification: ['identifier', 'value', 'expiresAt', 'createdAt', 'updatedAt'],
  rateLimit: ['key', 'count', 'lastRequest'],
}

/** Default slug for a custom model collection. */
export function defaultCustomSlug(model: string): string {
  return `ba-${model}`
}

/** Validated collection slug for a custom model declaration. */
export function customModelSlug(entry: BetterAuthCustomModel): string {
  const slug = entry.slug ?? defaultCustomSlug(entry.model)
  if (slug === '') {
    throw new InvalidConfigError(`custom model "${entry.model}" slug must not be empty`)
  }
  return slug
}

/**
 * The Better Auth id of a row. Payload owns the numeric document `id`, so
 * the adapter keeps the provider id in this unique field and translates
 * `id` <-> `baId` at the boundary.
 */
function baIdField(): Field {
  return { name: 'baId', type: 'text', required: true, unique: true, index: true }
}

function base(
  slug: string,
  label: string,
  fields: Field[],
  access: BetterAuthCollectionsAccess | undefined
): CollectionConfig {
  return {
    slug,
    labels: { singular: label, plural: `${label}s` },
    admin: {
      hidden: true,
      description: `System table managed by the Better Auth adapter. Do not edit.`,
    },
    access: access ?? denyAllAccess(),
    fields: [baIdField(), ...fields],
  }
}

const reservedFieldNames: ReadonlySet<string> = new Set(['id', 'baId', 'createdAt', 'updatedAt'])

function toPayloadField(field: BetterAuthCustomField): Field {
  const shared = { name: field.name, required: field.required ?? false }
  const indexed =
    field.unique === true &&
    (field.type === 'text' || field.type === 'number' || field.type === 'date')
      ? { unique: true, index: true }
      : {}
  switch (field.type) {
    case 'text':
      return { ...shared, type: 'text', ...indexed }
    case 'number':
      return { ...shared, type: 'number', ...indexed }
    case 'boolean':
      return { ...shared, type: 'checkbox' }
    case 'date':
      return { ...shared, type: 'date', ...indexed }
    case 'json':
      return { ...shared, type: 'json' }
  }
}

function checkCustomFields(
  owner: string,
  fields: readonly BetterAuthCustomField[],
  coreNames: readonly string[]
): void {
  const seen = new Set<string>()
  for (const field of fields) {
    if (field.name === '') {
      throw new InvalidConfigError(`${owner}: custom field name must not be empty`)
    }
    if (reservedFieldNames.has(field.name) || coreNames.includes(field.name)) {
      throw new InvalidConfigError(
        `${owner}: custom field "${field.name}" collides with a built-in field`
      )
    }
    if (seen.has(field.name)) {
      throw new InvalidConfigError(`${owner}: duplicate custom field "${field.name}"`)
    }
    seen.add(field.name)
  }
}

/**
 * Payload collections backing the five Better Auth core models plus any
 * declared custom fields and custom models. Spread the result into the
 * Payload config `collections` array; the engine wires the adapter
 * against the same slugs.
 *
 * Field lists mirror Better Auth's canonical schema; the adapter rejects
 * renamed models/fields, undeclared extras, and declared-but-absent names
 * fail-fast at startup.
 */
export function createBetterAuthCollections(
  options?: BetterAuthCollectionsOptions
): CollectionConfig[] {
  const slugs: BetterAuthCollectionSlugs = resolveSlugs(defaultBetterAuthSlugs, options?.slugs)
  const customFields = options?.customFields ?? {}
  const customModels = options?.customModels ?? []
  assertUniqueSlugs(
    {
      ...slugs,
      ...Object.fromEntries(customModels.map((entry) => [entry.model, customModelSlug(entry)])),
    },
    'Better Auth collections'
  )
  const coreKeys = new Set(Object.keys(betterAuthCoreFields))
  const seenModels = new Set<string>()
  for (const entry of customModels) {
    if (entry.model === '') {
      throw new InvalidConfigError('custom model name must not be empty')
    }
    if (coreKeys.has(entry.model)) {
      throw new InvalidConfigError(
        `custom model "${entry.model}" collides with a core model; declare fields via customFields instead`
      )
    }
    if (seenModels.has(entry.model)) {
      throw new InvalidConfigError(`duplicate custom model "${entry.model}"`)
    }
    seenModels.add(entry.model)
    checkCustomFields(`custom model "${entry.model}"`, entry.fields, [])
  }
  const extra = (model: BetterAuthModelKey): Field[] => {
    const declared = customFields[model] ?? []
    checkCustomFields(`customFields.${model}`, declared, betterAuthCoreFields[model])
    return declared.map(toPayloadField)
  }
  return [
    base(
      slugs.user,
      'Better Auth user',
      [
        { name: 'email', type: 'email', required: true, unique: true, index: true },
        { name: 'name', type: 'text', required: true },
        { name: 'emailVerified', type: 'checkbox', required: true, defaultValue: false },
        { name: 'image', type: 'text' },
        ...extra('user'),
      ],
      options?.access
    ),
    base(
      slugs.session,
      'Better Auth session',
      [
        { name: 'userId', type: 'text', required: true, index: true },
        { name: 'token', type: 'text', required: true, unique: true, index: true },
        { name: 'expiresAt', type: 'date', required: true },
        { name: 'ipAddress', type: 'text' },
        { name: 'userAgent', type: 'text' },
        ...extra('session'),
      ],
      options?.access
    ),
    base(
      slugs.account,
      'Better Auth account',
      [
        { name: 'userId', type: 'text', required: true, index: true },
        { name: 'accountId', type: 'text', required: true, index: true },
        { name: 'providerId', type: 'text', required: true, index: true },
        { name: 'password', type: 'text' },
        { name: 'accessToken', type: 'text' },
        { name: 'refreshToken', type: 'text' },
        { name: 'idToken', type: 'text' },
        { name: 'accessTokenExpiresAt', type: 'date' },
        { name: 'refreshTokenExpiresAt', type: 'date' },
        { name: 'scope', type: 'text' },
        ...extra('account'),
      ],
      options?.access
    ),
    base(
      slugs.verification,
      'Better Auth verification',
      [
        { name: 'identifier', type: 'text', required: true, index: true },
        { name: 'value', type: 'text', required: true },
        { name: 'expiresAt', type: 'date', required: true },
        ...extra('verification'),
      ],
      options?.access
    ),
    base(
      slugs.rateLimit,
      'Better Auth rate limit',
      [
        { name: 'key', type: 'text', required: true, unique: true, index: true },
        { name: 'count', type: 'number', required: true },
        { name: 'lastRequest', type: 'number', required: true },
        ...extra('rateLimit'),
      ],
      options?.access
    ),
    ...customModels.map((entry) =>
      base(
        customModelSlug(entry),
        entry.label ?? `Better Auth ${entry.model}`,
        entry.fields.map(toPayloadField),
        options?.access
      )
    ),
  ]
}
