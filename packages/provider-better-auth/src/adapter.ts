import { randomUUID } from 'node:crypto'
import { assertUniqueSlugs, isRecord, resolveSlugs } from '@payload-auth-link/core'
import type { BetterAuthOptions } from 'better-auth'
import {
  createAdapterFactory,
  type AdapterFactory,
  type AdapterFactoryCustomizeAdapterCreator,
  type CleanedWhere,
  type CustomAdapter,
  type JoinConfig,
} from 'better-auth/adapters'
import type { Payload, Where } from 'payload'
import {
  betterAuthCoreFields,
  customModelSlug,
  defaultBetterAuthSlugs,
  type BetterAuthCollectionSlugs,
  type BetterAuthCustomField,
  type BetterAuthCustomModel,
  type BetterAuthModelKey,
  type BetterAuthSchemaMap,
} from './collections.js'
import { AdapterOperationError, UnknownModelError, UnsupportedSchemaError } from './errors.js'
import { translateWhereClause } from './where.js'

/** Database adapter wiring: Payload access, slugs, read depth. */
export type PayloadDatabaseAdapterDeps = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Collection slugs per model. Defaults to {@link defaultBetterAuthSlugs}. */
  readonly slugs?: Partial<BetterAuthCollectionSlugs> | undefined
  /**
   * Adopt existing collections for these models (issue #49): the
   * adapter serves the model from the host slug, maps renamed fields,
   * and — with `idStrategy: 'payload'` — uses the Payload document id
   * as the Better Auth row id. No `ba-*` collection exists for an
   * adopted model.
   */
  readonly schemaMap?: BetterAuthSchemaMap | undefined
  /**
   * `'payload'` (adopted models only) makes the Payload document id
   * the Better Auth row id, so ids never move. `'ba'` (the default)
   * keeps the provider id in the dedicated `baId` column of the
   * collections the engine creates.
   */
  readonly idStrategy?: 'ba' | 'payload' | undefined
  /** Payload query depth for adapter reads. Rows are flat; defaults to 0. */
  readonly depth?: number | undefined
  /** Declared custom fields on core models; must match the BA schema exactly. */
  readonly customFields?:
    Partial<Record<BetterAuthModelKey, readonly BetterAuthCustomField[]>> | undefined
  /** Declared custom plugin models; must match the BA schema exactly. */
  readonly customModels?: readonly BetterAuthCustomModel[] | undefined
}

type CreatorContext = Parameters<AdapterFactoryCustomizeAdapterCreator>[0]

const coreModels: readonly BetterAuthModelKey[] = [
  'user',
  'session',
  'account',
  'verification',
  'rateLimit',
]

function isModelKey(key: string): key is BetterAuthModelKey {
  return coreModels.some((model) => model === key)
}

/**
 * Core allowlist (shared with the collections). Anything else in the
 * schema must be a declared custom field or custom model — undeclared
 * extras fail fast, since there is no Payload column for them.
 */
const coreFields: Record<BetterAuthModelKey, readonly string[]> = betterAuthCoreFields

type ValidatedSchema = {
  /** `date`-typed fields per model, e.g. `session.expiresAt`. */
  readonly dateFields: ReadonlySet<string>
  /** Every Better Auth field name per model (`id` excluded). */
  readonly baFields: ReadonlyMap<string, ReadonlySet<string>>
}

/**
 * Everything the adapter needs to serve one model. Adopted models
 * resolve slugs, field names, and ids through the schema map
 * (issue #49); engine-created models keep the classic `baId` layout.
 */
type ModelPlan = {
  readonly slug: string
  readonly adopted: boolean
  /** The Payload document id doubles as the Better Auth row id. */
  readonly payloadId: boolean
  /** Better Auth field name → Payload field name (identity unless mapped). */
  readonly baToPayload: Readonly<Record<string, string>>
  /** Payload field name → Better Auth field name (reverse of the above). */
  readonly payloadToBa: Readonly<Record<string, string>>
  /**
   * Set by host validation (issue #49): the adopted collection is a
   * Payload AUTH collection with the local strategy still enabled, so
   * Better Auth's creates must hand Payload a password (Payload's
   * local registration demands one). The value is unknowable random
   * bytes — the same pattern the plugin's own repository uses for
   * provider-provisioned users; nobody can sign into it.
   */
  injectPasswordOnCreate: boolean
}

function planFor(
  model: string,
  slugs: Readonly<Record<string, string>>,
  schemaMap: BetterAuthSchemaMap,
  idStrategy: 'ba' | 'payload'
): ModelPlan {
  const adopted = schemaMap[model]
  const baToPayload: Record<string, string> = { ...(adopted?.fields ?? {}) }
  baToPayload.id = adopted !== undefined && idStrategy === 'payload' ? 'id' : 'baId'
  const payloadToBa: Record<string, string> = {}
  for (const [ba, payload] of Object.entries(adopted?.fields ?? {})) {
    payloadToBa[payload] = ba
  }
  const slug: string | undefined = adopted?.slug ?? slugs[model]
  if (slug === undefined) {
    throw new UnknownModelError(model)
  }
  return {
    slug,
    adopted: adopted !== undefined,
    payloadId: adopted !== undefined && idStrategy === 'payload',
    baToPayload,
    payloadToBa,
    injectPasswordOnCreate: false,
  }
}

type CustomSchema = {
  readonly fields: Partial<Record<BetterAuthModelKey, readonly BetterAuthCustomField[]>>
  readonly models: readonly BetterAuthCustomModel[]
}

function validateTableFields(
  model: string,
  table: { fields: Record<string, { type: unknown }> },
  allowed: ReadonlySet<string>,
  declared: readonly BetterAuthCustomField[],
  dateFields: Set<string>
): void {
  for (const [field, attribute] of Object.entries(table.fields)) {
    if (field !== 'id' && !allowed.has(field)) {
      throw new UnsupportedSchemaError(
        `field "${model}.${field}" has no Payload column; declare it in customFields/customModels or drop the customization`
      )
    }
    if (attribute.type === 'date') {
      dateFields.add(`${model}.${field}`)
    }
  }
  for (const entry of declared) {
    if (!Object.hasOwn(table.fields, entry.name)) {
      throw new UnsupportedSchemaError(
        `declared field "${model}.${entry.name}" is missing from the Better Auth schema; check the name`
      )
    }
  }
}

function validateSchema(
  ctx: CreatorContext,
  custom: CustomSchema,
  adoptedKeys: ReadonlySet<string>
): ValidatedSchema {
  const dateFields = new Set<string>()
  const baFields = new Map<string, Set<string>>()
  for (const model of coreModels) {
    const table = ctx.schema[model]
    if (!table) {
      // `rateLimit` only exists with database-backed rate limiting.
      if (model === 'rateLimit') {
        continue
      }
      throw new UnsupportedSchemaError(`missing table for model "${model}"`)
    }
    baFields.set(model, new Set(Object.keys(table.fields).filter((field) => field !== 'id')))
    if (ctx.getModelName(model) !== model && !adoptedKeys.has(model)) {
      throw new UnsupportedSchemaError(
        `model "${model}" is renamed to "${ctx.getModelName(model)}"; custom model names need matching Payload collections`
      )
    }
    for (const field of coreFields[model]) {
      const physical = ctx.getFieldName({ model, field })
      if (physical !== field) {
        throw new UnsupportedSchemaError(
          `field "${model}.${field}" is renamed to "${physical}"; custom field names need matching Payload fields`
        )
      }
    }
    const declared = custom.fields[model] ?? []
    validateTableFields(
      model,
      table,
      new Set([...coreFields[model], ...declared.map((entry) => entry.name)]),
      declared,
      dateFields
    )
  }
  for (const entry of custom.models) {
    const table = ctx.schema[entry.model]
    if (!table) {
      throw new UnsupportedSchemaError(
        `missing table for custom model "${entry.model}"; enable the plugin that registers it`
      )
    }
    baFields.set(entry.model, new Set(Object.keys(table.fields).filter((field) => field !== 'id')))
    if (ctx.getModelName(entry.model) !== entry.model && !adoptedKeys.has(entry.model)) {
      throw new UnsupportedSchemaError(
        `model "${entry.model}" is renamed to "${ctx.getModelName(entry.model)}"; custom model names need matching Payload collections`
      )
    }
    validateTableFields(
      entry.model,
      table,
      // Payload owns the row timestamps; everything else must be declared.
      new Set([...entry.fields.map((field) => field.name), 'createdAt', 'updatedAt']),
      entry.fields,
      dateFields
    )
  }
  const declared = new Set([...coreModels, ...custom.models.map((entry) => entry.model)])
  for (const name of Object.keys(ctx.schema)) {
    if (!declared.has(name)) {
      throw new UnsupportedSchemaError(
        `model "${name}" is not declared; add it to customModels with its fields or drop the plugin`
      )
    }
  }
  return { dateFields, baFields }
}

function resolveModel(
  modelKey: string | undefined,
  model: string,
  customModels: ReadonlySet<string>,
  adoptedModels: ReadonlySet<string> = new Set()
): string {
  const key = modelKey ?? model
  if (!isModelKey(key) && !customModels.has(key) && !adoptedModels.has(key)) {
    throw new UnknownModelError(key)
  }
  return key
}

function isDateField(dates: ReadonlySet<string>, model: string, field: string): boolean {
  return dates.has(`${model}.${field}`)
}

/** Narrow a Payload document; Payload results are untyped here. */
function narrowDoc(value: unknown, operation: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new AdapterOperationError(`${operation}: expected a document, received ${typeof value}`)
  }
  return value
}

/** Narrow a `find` result to its document records. */
function narrowDocList(result: unknown, operation: string): Record<string, unknown>[] {
  if (!isRecord(result) || !Array.isArray(result.docs)) {
    throw new AdapterOperationError(`${operation}: expected a result with a docs array`)
  }
  const docs: unknown[] = result.docs
  return docs.map((doc) => narrowDoc(doc, operation))
}

/** Narrow a bulk `update`/`delete` result to docs plus error messages. */
function narrowBulkResult(
  result: unknown,
  operation: string
): { docs: Record<string, unknown>[]; errors: string[] } {
  if (!isRecord(result) || !Array.isArray(result.docs) || !Array.isArray(result.errors)) {
    throw new AdapterOperationError(`${operation}: expected a bulk result with docs and errors`)
  }
  const docs: unknown[] = result.docs
  const errors: unknown[] = result.errors
  return {
    docs: docs.map((doc) => narrowDoc(doc, operation)),
    errors: errors.map((entry) => {
      if (!isRecord(entry) || typeof entry.message !== 'string') {
        throw new AdapterOperationError(`${operation}: malformed bulk error entry`)
      }
      return entry.message
    }),
  }
}

/** Narrow a `count` result to its total. */
function narrowCount(result: unknown, operation: string): number {
  if (!isRecord(result) || typeof result.totalDocs !== 'number') {
    throw new AdapterOperationError(`${operation}: expected a count result with totalDocs`)
  }
  return result.totalDocs
}

function readPayloadId(doc: Record<string, unknown>, operation: string): string | number {
  const id = doc.id
  if (typeof id !== 'string' && typeof id !== 'number') {
    throw new AdapterOperationError(`${operation}: missing Payload document id`)
  }
  return id
}

/**
 * Map a Payload document to a Better Auth row: the persisted id becomes
 * `id` (`baId`, or the document `id` for adopted models under
 * `idStrategy: 'payload'`), Payload field names become Better Auth
 * names through the model plan, id-bearing fields are normalized to
 * strings (Better Auth compares row ids as strings), and `date` fields
 * become `Date` instances (matching the memory adapter's in-memory
 * semantics). With `select`, only the selected Better Auth fields are
 * kept. Storage drift (a row without its id, an unparseable date)
 * throws `AdapterOperationError` here instead of reaching Better Auth
 * as a malformed row.
 */
function toBaRow(
  dates: ReadonlySet<string>,
  model: string,
  plan: ModelPlan,
  doc: Record<string, unknown>,
  idFields: ReadonlySet<string>,
  select?: readonly string[]
): Record<string, unknown> {
  const include = (field: string): boolean => select === undefined || select.includes(field)
  const row: Record<string, unknown> = {}
  if (include('id')) {
    const persisted = plan.payloadId ? doc.id : doc.baId
    if (
      (typeof persisted !== 'string' && typeof persisted !== 'number') ||
      persisted === '' ||
      persisted === null
    ) {
      throw new AdapterOperationError(`${model} row: missing ${plan.payloadId ? 'id' : 'baId'}`)
    }
    row.id = String(persisted)
  }
  for (const [key, value] of Object.entries(doc)) {
    if (key === 'id' || key === 'baId') {
      continue
    }
    const baName: string = plan.payloadToBa[key] ?? key
    if (!include(baName)) {
      continue
    }
    if (isDateField(dates, model, baName) && typeof value === 'string') {
      const date = new Date(value)
      if (Number.isNaN(date.getTime())) {
        throw new AdapterOperationError(`${model} row: ${baName} is not a valid date`)
      }
      row[baName] = date
      continue
    }
    row[baName] = idFields.has(baName) && typeof value === 'number' ? String(value) : value
  }
  return row
}

/**
 * Narrow Better Auth input to a record, then map it to Payload data: `id`
 * becomes `baId` on create for engine-created models (dropped outright
 * for adopted models under `idStrategy: 'payload'` — Payload owns the
 * id, and the created document's id comes back as the row id),
 * Payload-owned timestamps are dropped, field names resolve through the
 * model plan, id-bearing relationship fields are coerced to the
 * Payload id type, and `Date` instances become ISO strings. Only
 * Better Auth fields are ever written — host-only fields on adopted
 * collections are invisible here and therefore survive every write
 * (issue #49).
 */
function toPayloadData(
  value: unknown,
  plan: ModelPlan,
  options: {
    forCreate: boolean
    idCoerce: (field: string, value: unknown) => unknown
  }
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new AdapterOperationError('write: expected a data object')
  }
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) {
    if (key === 'id') {
      if (options.forCreate && !plan.payloadId) {
        out.baId = entry
      }
      continue
    }
    if (key === 'createdAt' || key === 'updatedAt') {
      continue
    }
    const payloadName: string = plan.baToPayload[key] ?? key
    out[payloadName] = entry instanceof Date ? entry.toISOString() : options.idCoerce(key, entry)
  }
  if (options.forCreate && plan.injectPasswordOnCreate && out.password === undefined) {
    // Adopted AUTH collection with Payload's local strategy on: Payload
    // requires a password at create. A random one keeps the local
    // credential unusable — the provider owns authentication here —
    // while the create satisfies the strategy's contract.
    out.password = randomUUID()
  }
  return out
}

const joinLimitDefault = 100

/**
 * Attach joined rows under the physical join-model name, mirroring the
 * memory adapter: `one-to-one` nests a single row or `null`, otherwise an
 * array capped at `limit` (default 100). One query per base row — joins
 * are rare in core flows, so clarity wins over batching here.
 */
async function applyJoin(
  payload: Payload,
  dates: ReadonlySet<string>,
  depth: number,
  rows: Record<string, unknown>[],
  join: JoinConfig,
  customModels: ReadonlySet<string>,
  planOfJoin: (model: string) => ModelPlan,
  idFieldsOfJoin: (model: string) => ReadonlySet<string>
): Promise<Record<string, unknown>[]> {
  const entries = Object.entries(join)
  if (entries.length === 0) {
    return rows
  }
  return Promise.all(
    rows.map(async (row) => {
      const nested: Record<string, unknown> = { ...row }
      for (const [joinModel, config] of entries) {
        const joinKey = resolveModel(config.modelKey, joinModel, customModels)
        const joinPlan = planOfJoin(joinKey)
        const joinField = joinPlan.baToPayload[config.on.to] ?? config.on.to
        const where: Where = {
          [joinField]: { equals: row[config.on.from] },
        }
        const found: unknown = await payload.find({
          collection: joinPlan.slug,
          where,
          limit: config.limit ?? joinLimitDefault,
          depth,
          pagination: false,
          overrideAccess: true,
        })
        const joined = narrowDocList(found, `join ${joinModel}`).map((doc) =>
          toBaRow(dates, joinKey, joinPlan, doc, idFieldsOfJoin(joinKey))
        )
        nested[joinModel] = config.relation === 'one-to-one' ? (joined[0] ?? null) : joined
      }
      return nested
    })
  )
}

/**
 * Re-type a built row as the caller-declared model type. `T` is
 * instantiated by Better Auth core with the row type of the queried model;
 * rows are built field-by-field by `toBaRow` (which asserts `id` and date
 * fields), and integration tests prove each model round-trips. The shape
 * is still asserted here — a record, `null`, or an array of records — so
 * no non-row value is ever re-typed as one.
 */
function asModelRow<T>(row: unknown): T {
  const isRow = (value: unknown): boolean => isRecord(value) && !Array.isArray(value)
  if (row !== null && !isRow(row) && !(Array.isArray(row) && row.every(isRow))) {
    throw new AdapterOperationError('model row: expected a row object, null, or a row array')
  }
  return row as T
}

function rethrowAsOperation(
  error: unknown,
  operation: string
): AdapterOperationError | UnknownModelError {
  if (error instanceof UnknownModelError || error instanceof AdapterOperationError) {
    return error
  }
  return new AdapterOperationError(operation, { cause: error })
}

/**
 * Better Auth database adapter over the Payload Local API. System-level
 * persistence (like the plugin repository): reads and writes bypass access
 * control with `overrideAccess`, and the collections default to deny-all
 * API access.
 *
 * The returned factory is passed as Better Auth's `database` option; the
 * factory validates the Better Auth schema against the Payload mapping
 * when the instance is created, failing fast on renames and unmapped
 * fields. Transactions run sequentially (Payload commits per operation).
 *
 * Query semantics match Better Auth's reference `memoryAdapter` (pinned
 * by `adapter-differential.test.ts`) with these documented differences:
 *
 * - **String sort collation is the database's, not `localeCompare`.**
 *   `findMany({ sortBy })` delegates ordering to Payload, which exposes
 *   no portable collation option: SQLite and MongoDB order by binary
 *   (code point: `'A' < 'B' < 'a' < 'b'`), Postgres by the column's
 *   collation (often locale-aware). The memory adapter orders with
 *   `String.prototype.localeCompare` (`'a' < 'A' < 'b' < 'B'`).
 *   Normalising in memory would break `limit`/`offset` pagination (the
 *   window is cut by the database), so the difference is documented
 *   rather than papered over. Better Auth core issues no string-sorted
 *   paged reads; numbers, dates, and same-case strings agree.
 * - **`null` ordering** follows the database (SQLite/MongoDB: first in
 *   ascending order, like the memory adapter; Postgres: last).
 * - **String range operators** (`lt`/`lte`/`gt`/`gte` on text) compare
 *   in the same database collation as sorting; the memory adapter
 *   compares JS strings. Same-case ASCII strings agree everywhere.
 *
 * Agreeing by construction (pinned by the same suite, #110): `ne` and
 * `not_in` keep `NULL` rows (the `not_in` translation adds an
 * `IS NULL` branch), and case-insensitive `eq` decides in JS, so it is
 * Unicode-aware on SQLite, whose `LIKE` folds ASCII only.
 * - **Unordered reads** (no `sortBy`) return rows in Payload's default
 *   order, not insertion order; callers must not rely on either.
 * - **Pattern operators** (`contains`, `starts_with`, `ends_with`),
 *   case-insensitive `ne`/`in`/`not_in`, and a case-insensitive `eq`
 *   combined with an `OR` connector throw `UnsupportedOperatorError`
 *   rather than risk a silently wrong translation.
 */
export function createPayloadDatabaseAdapter(
  deps: PayloadDatabaseAdapterDeps
): AdapterFactory<BetterAuthOptions> {
  const customModels = deps.customModels ?? []
  const customFields = deps.customFields ?? {}
  const customNames = new Set(customModels.map((entry) => entry.model))
  const schemaMap = deps.schemaMap ?? {}
  if (deps.idStrategy === 'payload' && Object.keys(schemaMap).length === 0) {
    throw new UnsupportedSchemaError(
      "idStrategy 'payload' applies to adopted models; pass a schemaMap entry (issue #49)"
    )
  }
  const coreSlugs = resolveSlugs(defaultBetterAuthSlugs, deps.slugs)
  const slugs: Record<string, string> = {
    ...coreSlugs,
    ...Object.fromEntries(customModels.map((entry) => [entry.model, customModelSlug(entry)])),
    ...Object.fromEntries(Object.entries(schemaMap).map(([model, entry]) => [model, entry.slug])),
  }
  assertUniqueSlugs(slugs, 'Better Auth adapter')
  const depth = deps.depth ?? 0
  const idStrategy = deps.idStrategy ?? 'ba'
  const adoptedKeys = new Set(Object.keys(schemaMap))
  const plans = new Map<string, ModelPlan>()
  const planOf = (model: string): ModelPlan => {
    const existing = plans.get(model)
    if (existing !== undefined) {
      return existing
    }
    const plan = planFor(model, slugs, schemaMap, idStrategy)
    plans.set(model, plan)
    return plan
  }
  // Id-bearing fields per model: every field the schema map renames on
  // an adopted model carries a document reference (userId → user,
  // organizationId → organization), so reads normalize to strings and
  // writes coerce to the Payload id type. Populated once the host
  // collections are validated (relationship classification needs the
  // host field types).
  const idFieldsByModel = new Map<string, Set<string>>()
  const idFieldsOf = (model: string): ReadonlySet<string> => {
    const declared = idFieldsByModel.get(model)
    if (declared !== undefined) {
      return declared
    }
    const fallback = new Set<string>(
      Object.keys(schemaMap[model]?.fields ?? {}).filter((field) => field !== 'id')
    )
    idFieldsByModel.set(model, fallback)
    return fallback
  }
  /**
   * Write-side id coercion for one model: relationship fields receive
   * Better Auth's string ids and must hand Payload the id type the host
   * collection uses. Classification lands after host validation; before
   * that the fields pass through untouched (a string id is also the
   * correct input for a text id column).
   */
  const idCoerceFor =
    (model: string) =>
    (field: string, value: unknown): unknown => {
      if (!idFieldsOf(model).has(field) || typeof value !== 'string') {
        return value
      }
      const numeric = Number(value)
      return value !== '' && Number.isSafeInteger(numeric) ? numeric : value
    }

  /**
   * First-use validation of the host collections backing adopted
   * models (issue #49): every Better Auth field must resolve to a host
   * Payload field — through the field map when renamed, by name
   * otherwise — and renamed fields are classified by the host field
   * type (a relationship carries document ids: reads normalize to
   * strings, writes coerce to the Payload id type). Fails fast on the
   * first adapter operation, naming the model and field; memoized per
   * adapter instance.
   */
  /**
   * Local-strategy detection for adopted AUTH collections (see
   * {@link ModelPlan.injectPasswordOnCreate}). Runs with host
   * validation, once.
   */
  const markLocalStrategyCollections = (payload: Payload): void => {
    for (const plan of plans.values()) {
      if (!plan.adopted) {
        continue
      }
      const collection = payload.collections[plan.slug]
      const auth: unknown = collection?.config?.auth
      const localOn =
        auth === true ||
        (typeof auth === 'object' &&
          auth !== null &&
          !Array.isArray(auth) &&
          (auth as { disableLocalStrategy?: unknown }).disableLocalStrategy !== true)
      plan.injectPasswordOnCreate = localOn
    }
  }
  let hostValidation: Promise<void> | undefined
  const runHostValidation = (payload: Payload, baFields: ValidatedSchema['baFields']): void => {
    {
      markLocalStrategyCollections(payload)
      const hostCache = new Map<string, Map<string, string>>()
      const hostFieldTypes = (slug: string): Map<string, string> => {
        const cached = hostCache.get(slug)
        if (cached !== undefined) {
          return cached
        }
        const collection = payload.collections[slug]
        if (collection === undefined) {
          throw new UnsupportedSchemaError(
            `adopted model expects collection "${slug}", which the Payload config does not define`
          )
        }
        const types = new Map<string, string>()
        const walk = (fields: unknown): void => {
          if (!Array.isArray(fields)) {
            return
          }
          for (const field of fields) {
            if (!isRecord(field) || typeof field.name !== 'string' || field.name === '') {
              continue
            }
            if (field.type === 'ui' || field.type === 'tabs') {
              if (field.type === 'tabs') {
                walk(field.tabs)
              }
              continue
            }
            types.set(field.name, typeof field.type === 'string' ? field.type : 'unknown')
          }
        }
        walk(collection.config?.fields)
        hostCache.set(slug, types)
        return types
      }
      for (const [model, plan] of plans) {
        if (!plan.adopted) {
          continue
        }
        const fieldTypes = hostFieldTypes(plan.slug)
        const mapped = schemaMap[model]?.fields ?? {}
        for (const [baName, payloadName] of Object.entries(mapped)) {
          if (!fieldTypes.has(payloadName)) {
            throw new UnsupportedSchemaError(
              `adopted model "${model}" maps "${baName}" to "${plan.slug}.${payloadName}", which the host collection does not define`
            )
          }
        }
        const idFields = new Set<string>()
        for (const baName of baFields.get(model) ?? new Set<string>()) {
          const payloadName = plan.baToPayload[baName] ?? baName
          if (payloadName === 'id' || payloadName === 'baId') {
            continue
          }
          const fieldType = fieldTypes.get(payloadName)
          if (fieldType === undefined) {
            throw new UnsupportedSchemaError(
              `adopted model "${model}" needs a "${plan.slug}.${payloadName}" field for Better Auth's "${baName}"; add it to the host collection or map it in the schemaMap`
            )
          }
          if (fieldType === 'relationship') {
            idFields.add(baName)
          }
        }
        idFieldsByModel.set(model, idFields)
      }
    }
  }
  const validateHostCollections = (
    payload: Payload,
    baFields: ValidatedSchema['baFields']
  ): Promise<void> => {
    // Memoized as a promise: every adapter operation awaits the same
    // validation, and the first failure rejects for all of them.
    hostValidation ??= Promise.resolve(runHostValidation(payload, baFields))
    return hostValidation
  }

  return createAdapterFactory<BetterAuthOptions>({
    config: { adapterId: 'payload-auth-link', adapterName: 'Payload CMS' },
    adapter: (ctx: CreatorContext): CustomAdapter => {
      const { dateFields, baFields } = validateSchema(
        ctx,
        { fields: customFields, models: customModels },
        adoptedKeys
      )
      const payloadOf = (): Promise<Payload> =>
        deps.getPayload().then(async (payload) => {
          await validateHostCollections(payload, baFields)
          return payload
        })

      const findRawOne = async (
        plan: ModelPlan,
        where: Where
      ): Promise<Record<string, unknown> | undefined> => {
        const payload = await payloadOf()
        const found: unknown = await payload.find({
          collection: plan.slug,
          where,
          limit: 1,
          depth,
          pagination: false,
          overrideAccess: true,
        })
        const [doc] = narrowDocList(found, 'findRawOne')
        return doc
      }

      /**
       * First raw document exactly matching a translated where plus its
       * post-filter. Mirrors `findBaOne`'s candidate window (a
       * case-insensitive `like` narrows, the post-filter exacts), so a
       * single-row mutation touches exactly the row a read would return
       * — never a `like` over-match.
       */
      const findRawExactOne = async (
        model: string,
        plan: ModelPlan,
        translated: Where,
        postFilter: (row: Record<string, unknown>) => boolean
      ): Promise<Record<string, unknown> | undefined> => {
        const payload = await payloadOf()
        const found: unknown = await payload.find({
          collection: plan.slug,
          where: translated,
          limit: joinLimitDefault,
          depth,
          pagination: false,
          overrideAccess: true,
        })
        for (const doc of narrowDocList(found, `findRawExactOne ${model}`)) {
          if (postFilter(toBaRow(dateFields, model, plan, doc, idFieldsOf(model)))) {
            return doc
          }
        }
        return undefined
      }

      /**
       * Every Payload document id exactly matching a translated where
       * plus its post-filter, paged like `count`. Bulk mutations write
       * by this id set instead of the translated where, so a
       * case-insensitive `like` can never over-match into a
       * full-collection rewrite.
       */
      const findExactIds = async (
        model: string,
        plan: ModelPlan,
        translated: Where,
        postFilter: (row: Record<string, unknown>) => boolean
      ): Promise<Array<string | number>> => {
        const payload = await payloadOf()
        const ids: Array<string | number> = []
        let page = 1
        for (;;) {
          const found: unknown = await payload.find({
            collection: plan.slug,
            where: translated,
            limit: 1000,
            page,
            depth,
            pagination: true,
            overrideAccess: true,
          })
          if (!isRecord(found) || typeof found.hasNextPage !== 'boolean') {
            throw new AdapterOperationError(`exact match ${model}: expected a paginated result`)
          }
          for (const doc of narrowDocList(found, `exact match ${model}`)) {
            if (postFilter(toBaRow(dateFields, model, plan, doc, idFieldsOf(model)))) {
              ids.push(readPayloadId(doc, `exact match ${model}`))
            }
          }
          if (!found.hasNextPage) {
            return ids
          }
          page += 1
        }
      }

      const findBaOne = async (
        model: string,
        clauses: readonly CleanedWhere[],
        select?: readonly string[],
        join?: JoinConfig
      ): Promise<Record<string, unknown> | null> => {
        const payload = await payloadOf()
        const plan = planOf(model)
        const { where, postFilter } = translateWhereClause(
          clauses,
          (field) => plan.baToPayload[field] ?? field,
          idCoerceFor(model)
        )
        if (postFilter === undefined) {
          const found: unknown = await payload.find({
            collection: plan.slug,
            where,
            limit: 1,
            depth,
            pagination: false,
            overrideAccess: true,
          })
          let rows = narrowDocList(found, `findOne ${model}`).map((doc) =>
            toBaRow(dateFields, model, plan, doc, idFieldsOf(model), select)
          )
          if (join) {
            rows = await applyJoin(
              payload,
              dateFields,
              depth,
              rows,
              join,
              customNames,
              planOf,
              idFieldsOf
            )
          }
          return rows[0] ?? null
        }
        // Post-filtered queries page through the source with a stable
        // sort (issue #18): a fixed window can be all contains-match
        // decoys with the exact match past it.
        const filter = postFilter
        const pageSize = joinLimitDefault
        for (let page = 1; ; page += 1) {
          const found: unknown = await payload.find({
            collection: plan.slug,
            where,
            limit: pageSize,
            page,
            sort: 'id',
            depth,
            overrideAccess: true,
          })
          let rows = narrowDocList(found, `findOne ${model}`).map((doc) =>
            toBaRow(dateFields, model, plan, doc, idFieldsOf(model), select)
          )
          if (join) {
            rows = await applyJoin(
              payload,
              dateFields,
              depth,
              rows,
              join,
              customNames,
              planOf,
              idFieldsOf
            )
          }
          const match = rows.find((row) => filter(row))
          if (match !== undefined) {
            return match
          }
          if (rows.length < pageSize) {
            return null
          }
        }
      }

      return {
        create: async <T extends Record<string, unknown>>({
          model,
          modelKey,
          data,
          select,
        }: {
          model: string
          modelKey?: string | undefined
          data: T
          select?: string[] | undefined
        }): Promise<T> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          try {
            const payload = await payloadOf()
            const doc: unknown = await payload.create({
              collection: plan.slug,
              data: toPayloadData(data, plan, { forCreate: true, idCoerce: idCoerceFor(key) }),
              overrideAccess: true,
            })
            return asModelRow<T>(
              toBaRow(
                dateFields,
                key,
                plan,
                narrowDoc(doc, `create ${key}`),
                idFieldsOf(key),
                select
              )
            )
          } catch (error) {
            throw rethrowAsOperation(error, `create ${key}`)
          }
        },

        findOne: async <T>({
          model,
          modelKey,
          where,
          select,
          join,
        }: {
          model: string
          modelKey?: string | undefined
          where: CleanedWhere[]
          select?: string[] | undefined
          join?: JoinConfig | undefined
        }): Promise<T | null> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          try {
            return asModelRow<T | null>(await findBaOne(key, where, select, join))
          } catch (error) {
            throw rethrowAsOperation(error, `findOne ${key}`)
          }
        },

        findMany: async <T>({
          model,
          modelKey,
          where,
          limit,
          select,
          sortBy,
          offset,
          join,
        }: {
          model: string
          modelKey?: string | undefined
          where?: CleanedWhere[] | undefined
          limit: number
          select?: string[] | undefined
          sortBy?: { field: string; direction: 'asc' | 'desc' } | undefined
          offset?: number | undefined
          join?: JoinConfig | undefined
        }): Promise<T[]> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(
              where ?? [],
              (field) => plan.baToPayload[field] ?? field,
              idCoerceFor(key)
            )
            const skip = offset ?? 0
            const sort =
              sortBy === undefined
                ? undefined
                : `${sortBy.direction === 'desc' ? '-' : ''}${plan.baToPayload[sortBy.field] ?? sortBy.field}`
            // A post-filtered query (case-insensitive `eq` becomes a
            // contains-match) can over-match: a fixed window of
            // `skip + limit` rows may be all decoys, so real matches
            // past it vanish and offsets count unfiltered rows
            // (issue #18). Page through the source — with a stable
            // sort when the caller gave none — until `skip + limit`
            // FILTERED rows are collected or the source is exhausted.
            if (postFilter !== undefined) {
              const filter = postFilter
              const pageSize = joinLimitDefault
              const matched: T[] = []
              const need = skip + limit
              let page = 1
              while (matched.length < need) {
                const found: unknown = await payload.find({
                  collection: plan.slug,
                  where: translated,
                  limit: pageSize,
                  page,
                  ...(sort !== undefined ? { sort } : { sort: 'id' }),
                  depth,
                  overrideAccess: true,
                })
                let rows = narrowDocList(found, `findMany ${key}`).map((doc) =>
                  toBaRow(dateFields, key, plan, doc, idFieldsOf(key), select)
                )
                if (join) {
                  rows = await applyJoin(
                    payload,
                    dateFields,
                    depth,
                    rows,
                    join,
                    customNames,
                    planOf,
                    idFieldsOf
                  )
                }
                matched.push(...(rows.filter((row) => filter(row)) as T[]))
                if (rows.length < pageSize) {
                  break
                }
                page += 1
              }
              return asModelRow<T[]>(matched.slice(skip, skip + limit))
            }
            const found: unknown = await payload.find({
              collection: plan.slug,
              where: translated,
              limit: skip + limit,
              ...(sort === undefined ? {} : { sort }),
              depth,
              pagination: false,
              overrideAccess: true,
            })
            let rows = narrowDocList(found, `findMany ${key}`).map((doc) =>
              toBaRow(dateFields, key, plan, doc, idFieldsOf(key), select)
            )
            if (join) {
              rows = await applyJoin(
                payload,
                dateFields,
                depth,
                rows,
                join,
                customNames,
                planOf,
                idFieldsOf
              )
            }
            return asModelRow<T[]>(rows.slice(skip, skip + limit))
          } catch (error) {
            throw rethrowAsOperation(error, `findMany ${key}`)
          }
        },

        count: async ({ model, modelKey, where }): Promise<number> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(
              where ?? [],
              (field) => plan.baToPayload[field] ?? field,
              idCoerceFor(key)
            )
            if (!postFilter) {
              const counted: unknown = await payload.count({
                collection: plan.slug,
                where: translated,
                overrideAccess: true,
              })
              return narrowCount(counted, `count ${key}`)
            }
            let page = 1
            let total = 0
            for (;;) {
              const found: unknown = await payload.find({
                collection: plan.slug,
                where: translated,
                limit: 1000,
                page,
                depth,
                pagination: true,
                overrideAccess: true,
              })
              if (!isRecord(found) || typeof found.hasNextPage !== 'boolean') {
                throw new AdapterOperationError(`count ${key}: expected a paginated result`)
              }
              total += narrowDocList(found, `count ${key}`)
                .map((doc) => toBaRow(dateFields, key, plan, doc, idFieldsOf(key)))
                .filter(postFilter).length
              if (!found.hasNextPage) {
                return total
              }
              page += 1
            }
          } catch (error) {
            throw rethrowAsOperation(error, `count ${key}`)
          }
        },

        update: async <T>({
          model,
          modelKey,
          where,
          update,
        }: {
          model: string
          modelKey?: string | undefined
          where: CleanedWhere[]
          update: T
        }): Promise<T | null> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          if (where.length === 0) {
            return null
          }
          try {
            const { where: translated, postFilter } = translateWhereClause(
              where,
              (field) => plan.baToPayload[field] ?? field,
              idCoerceFor(key)
            )
            const existing = postFilter
              ? await findRawExactOne(key, plan, translated, postFilter)
              : await findRawOne(plan, translated)
            if (!existing) {
              return null
            }
            const payload = await payloadOf()
            const doc: unknown = await payload.update({
              collection: plan.slug,
              id: readPayloadId(existing, `update ${key}`),
              data: toPayloadData(update, plan, { forCreate: false, idCoerce: idCoerceFor(key) }),
              overrideAccess: true,
            })
            return asModelRow<T | null>(
              toBaRow(dateFields, key, plan, narrowDoc(doc, `update ${key}`), idFieldsOf(key))
            )
          } catch (error) {
            throw rethrowAsOperation(error, `update ${key}`)
          }
        },

        updateMany: async ({ model, modelKey, where, update }): Promise<number> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          if (where.length === 0) {
            return 0
          }
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(
              where,
              (field) => plan.baToPayload[field] ?? field,
              idCoerceFor(key)
            )
            const data = toPayloadData(update, plan, {
              forCreate: false,
              idCoerce: idCoerceFor(key),
            })
            if (postFilter) {
              const ids = await findExactIds(key, plan, translated, postFilter)
              if (ids.length === 0) {
                return 0
              }
              const result: unknown = await payload.update({
                collection: plan.slug,
                where: { id: { in: ids } },
                data,
                overrideAccess: true,
              })
              const bulk = narrowBulkResult(result, `updateMany ${key}`)
              if (bulk.errors.length > 0) {
                throw new AdapterOperationError(
                  `updateMany ${key}: ${bulk.errors.length} row(s) failed: ${bulk.errors.join('; ')}`
                )
              }
              return bulk.docs.length
            }
            const result: unknown = await payload.update({
              collection: plan.slug,
              where: translated,
              data,
              overrideAccess: true,
            })
            const bulk = narrowBulkResult(result, `updateMany ${key}`)
            if (bulk.errors.length > 0) {
              throw new AdapterOperationError(
                `updateMany ${key}: ${bulk.errors.length} row(s) failed: ${bulk.errors.join('; ')}`
              )
            }
            return bulk.docs.length
          } catch (error) {
            throw rethrowAsOperation(error, `updateMany ${key}`)
          }
        },

        delete: async ({ model, modelKey, where }): Promise<void> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          if (where.length === 0) {
            throw new AdapterOperationError(`delete ${key}: refusing empty where clause`)
          }
          try {
            const { where: translated, postFilter } = translateWhereClause(
              where,
              (field) => plan.baToPayload[field] ?? field,
              idCoerceFor(key)
            )
            const existing = postFilter
              ? await findRawExactOne(key, plan, translated, postFilter)
              : await findRawOne(plan, translated)
            if (!existing) {
              return
            }
            const payload = await payloadOf()
            await payload.delete({
              collection: plan.slug,
              id: readPayloadId(existing, `delete ${key}`),
              overrideAccess: true,
            })
          } catch (error) {
            throw rethrowAsOperation(error, `delete ${key}`)
          }
        },

        deleteMany: async ({ model, modelKey, where }): Promise<number> => {
          const key = resolveModel(modelKey, model, customNames, adoptedKeys)
          const plan = planOf(key)
          if (where.length === 0) {
            throw new AdapterOperationError(`deleteMany ${key}: refusing empty where clause`)
          }
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(
              where,
              (field) => plan.baToPayload[field] ?? field,
              idCoerceFor(key)
            )
            if (postFilter) {
              const ids = await findExactIds(key, plan, translated, postFilter)
              if (ids.length === 0) {
                return 0
              }
              const result: unknown = await payload.delete({
                collection: plan.slug,
                where: { id: { in: ids } },
                overrideAccess: true,
              })
              const bulk = narrowBulkResult(result, `deleteMany ${key}`)
              if (bulk.errors.length > 0) {
                throw new AdapterOperationError(
                  `deleteMany ${key}: ${bulk.errors.length} row(s) failed: ${bulk.errors.join('; ')}`
                )
              }
              return bulk.docs.length
            }
            const result: unknown = await payload.delete({
              collection: plan.slug,
              where: translated,
              overrideAccess: true,
            })
            const bulk = narrowBulkResult(result, `deleteMany ${key}`)
            if (bulk.errors.length > 0) {
              throw new AdapterOperationError(
                `deleteMany ${key}: ${bulk.errors.length} row(s) failed: ${bulk.errors.join('; ')}`
              )
            }
            return bulk.docs.length
          } catch (error) {
            throw rethrowAsOperation(error, `deleteMany ${key}`)
          }
        },

        createSchema: ({ file }): Promise<{ code: string; path: string }> =>
          Promise.resolve({
            code: '// Better Auth tables are Payload CMS collections (see createBetterAuthCollections).\n// Schema is managed by Payload migrations; nothing to generate.\n',
            path: file ?? 'better-auth-payload-schema.txt',
          }),
      } satisfies CustomAdapter
    },
  })
}
