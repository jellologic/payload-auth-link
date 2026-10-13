/**
 * Derive the engine's `customFields` / `customModels` declarations
 * from Better Auth's own schema (issue #17): `getAuthTables(options)`
 * is the same source the adapter validates against, so a derived
 * declaration cannot disagree with what BA will ask for. Hand
 * declarations stay available (and win on conflicts when
 * `autoDeclare` merges) — derivation is for builders who compose
 * many plugins and do not want to hand-copy field lists per BA bump.
 */
import { getAuthTables } from 'better-auth/db'
import {
  betterAuthCoreFields,
  type BetterAuthCustomField,
  type BetterAuthCustomFieldType,
  type BetterAuthCustomModel,
  type BetterAuthModelKey,
} from './collections.js'

type Tables = ReturnType<typeof getAuthTables>
type Attribute = Tables[string]['fields'][string]

/** Fields Payload owns end to end (timestamps, ids); never declared. */
export const payloadOwnedFields: ReadonlySet<string> = new Set(['id', 'createdAt', 'updatedAt'])

const coreModelKeys: ReadonlySet<string> = new Set(Object.keys(betterAuthCoreFields))

/** Whether a BA model key is one of the adapter's core models. */
export function isCoreModel(model: string): model is BetterAuthModelKey {
  return coreModelKeys.has(model)
}

function toCustomFieldType(attribute: Attribute): BetterAuthCustomFieldType {
  // BA's attribute.type is an open-ended string (plugins add their
  // own), so this is a deliberately total mapping, not a closed
  // switch: known scalars map 1:1, and everything else — arrays
  // (`string[]`), objects, enum-valued attributes — maps to a JSON
  // column. Enum values stay text on purpose: a Payload select would
  // freeze the vocabulary against BA's own runtime validation, and BA
  // owns value validation anyway.
  const known: Partial<Record<string, BetterAuthCustomFieldType>> = {
    string: 'text',
    number: 'number',
    boolean: 'boolean',
    date: 'date',
    json: 'json',
  }
  return known[String(attribute.type)] ?? 'json'
}

function toCustomField(field: string, attribute: Attribute): BetterAuthCustomField {
  const type = toCustomFieldType(attribute)
  // A BA defaultValue means BA fills the column itself, so the
  // storage column must stay nullable (NOT NULL would break the
  // insert BA issues before applying defaults).
  const required = attribute.required === true && attribute.defaultValue === undefined
  // Unique constraints need an indexable column type.
  const unique = attribute.unique === true && type !== 'json'
  return {
    name: field,
    type,
    ...(required ? { required: true } : {}),
    ...(unique ? { unique: true } : {}),
  }
}

/**
 * Pure derivation over a `getAuthTables` result: core models keep
 * their plugin-added fields, everything else becomes a custom model.
 * Model or field renames (`modelName` / `fieldName` overrides) throw:
 * the adapter serves canonical BA names, and silently declaring a
 * renamed table under its key would produce a collection BA never
 * queries — declare those by hand.
 */
export function declarationsFromTables(tables: Tables): {
  customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>>
  customModels: BetterAuthCustomModel[]
} {
  const customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>> = {}
  const customModels: BetterAuthCustomModel[] = []
  for (const [model, table] of Object.entries(tables)) {
    if (table.modelName !== model) {
      throw new Error(
        `deriveBetterAuthSchema: model "${model}" is renamed to "${table.modelName}"; ` +
          'declare renamed models by hand (the adapter serves canonical BA names)'
      )
    }
    const declared: BetterAuthCustomField[] = []
    for (const [field, attribute] of Object.entries(table.fields)) {
      if (attribute.fieldName !== undefined && attribute.fieldName !== field) {
        throw new Error(
          `deriveBetterAuthSchema: field "${model}.${field}" is renamed to "${attribute.fieldName}"; ` +
            'declare renamed fields by hand'
        )
      }
      if (payloadOwnedFields.has(field)) {
        continue
      }
      if (isCoreModel(model) && betterAuthCoreFields[model].includes(field)) {
        continue
      }
      declared.push(toCustomField(field, attribute))
    }
    if (isCoreModel(model)) {
      if (declared.length > 0) {
        customFields[model] = declared
      }
    } else if (declared.length > 0) {
      customModels.push({ model, fields: declared })
    }
  }
  return { customFields, customModels }
}

/**
 * Derive declarations for a Better Auth options object — the shape
 * the builder passes to `betterAuth`/`createBetterAuthEngine`, whose
 * plugin list determines the schema.
 */
export function deriveBetterAuthSchema(options: unknown): {
  customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>>
  customModels: BetterAuthCustomModel[]
} {
  return declarationsFromTables(getAuthTables(options as Parameters<typeof getAuthTables>[0]))
}
