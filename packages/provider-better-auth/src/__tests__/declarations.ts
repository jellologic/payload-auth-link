/**
 * Shared test helper: generate the engine's `customFields` /
 * `customModels` declarations from BA's live `getAuthTables` output —
 * never hand-copied — so integration tests boot any plugin set
 * exactly the way the schema probe proves it can be served.
 */
import type { getAuthTables } from 'better-auth/db'
import {
  betterAuthCoreFields,
  type BetterAuthCustomField,
  type BetterAuthCustomFieldType,
  type BetterAuthCustomModel,
  type BetterAuthModelKey,
} from '../collections.js'

type Tables = ReturnType<typeof getAuthTables>
type Attribute = Tables[string]['fields'][string]

/** Fields Payload owns end to end; the adapter drops them on write. */
export const payloadOwnedFields: ReadonlySet<string> = new Set(['id', 'createdAt', 'updatedAt'])
const coreModelKeys: ReadonlySet<string> = new Set(Object.keys(betterAuthCoreFields))

/** Whether a BA model key is one of the adapter's core models. */
export function isCoreModel(model: string): model is BetterAuthModelKey {
  return coreModelKeys.has(model)
}

function toCustomFieldType(
  model: string,
  field: string,
  attribute: Attribute
): BetterAuthCustomFieldType {
  switch (attribute.type) {
    case 'string':
      return 'text'
    case 'number':
      return 'number'
    case 'boolean':
      return 'boolean'
    case 'date':
      return 'date'
    case 'json':
      return 'json'
    default:
      throw new Error(
        `declarations: ${model}.${field} has unsupported BA type ${JSON.stringify(attribute.type)}`
      )
  }
}

function toCustomField(model: string, field: string, attribute: Attribute): BetterAuthCustomField {
  return {
    name: field,
    type: toCustomFieldType(model, field, attribute),
    ...(attribute.required === true ? { required: true } : {}),
    ...(attribute.unique === true ? { unique: true } : {}),
  }
}

/** Generate engine declarations from BA's live schema for a plugin set. */
export function generateDeclarations(tables: Tables): {
  customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>>
  customModels: BetterAuthCustomModel[]
} {
  const customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>> = {}
  const customModels: BetterAuthCustomModel[] = []
  for (const [model, table] of Object.entries(tables)) {
    if (table.modelName !== model) {
      throw new Error(`declarations: model "${model}" is renamed to "${table.modelName}"`)
    }
    const declared: BetterAuthCustomField[] = []
    for (const [field, attribute] of Object.entries(table.fields)) {
      if (attribute.fieldName !== undefined && attribute.fieldName !== field) {
        throw new Error(
          `declarations: field "${model}.${field}" is renamed to "${attribute.fieldName}"`
        )
      }
      if (payloadOwnedFields.has(field)) {
        continue
      }
      if (isCoreModel(model) && betterAuthCoreFields[model].includes(field)) {
        continue
      }
      declared.push(toCustomField(model, field, attribute))
    }
    if (isCoreModel(model)) {
      if (declared.length > 0) {
        customFields[model] = declared
      }
    } else {
      customModels.push({ model, fields: declared })
    }
  }
  return { customFields, customModels }
}
