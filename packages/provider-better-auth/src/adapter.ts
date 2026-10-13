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
} from './collections.js'
import { AdapterOperationError, UnknownModelError, UnsupportedSchemaError } from './errors.js'
import { baFieldToPayload, translateWhereClause } from './where.js'

/** Database adapter wiring: Payload access, slugs, read depth. */
export type PayloadDatabaseAdapterDeps = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Collection slugs per model. Defaults to {@link defaultBetterAuthSlugs}. */
  readonly slugs?: Partial<BetterAuthCollectionSlugs> | undefined
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

function validateSchema(ctx: CreatorContext, custom: CustomSchema): ValidatedSchema {
  const dateFields = new Set<string>()
  for (const model of coreModels) {
    const table = ctx.schema[model]
    if (!table) {
      // `rateLimit` only exists with database-backed rate limiting.
      if (model === 'rateLimit') {
        continue
      }
      throw new UnsupportedSchemaError(`missing table for model "${model}"`)
    }
    if (ctx.getModelName(model) !== model) {
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
    if (ctx.getModelName(entry.model) !== entry.model) {
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
  return { dateFields }
}

function resolveModel(
  modelKey: string | undefined,
  model: string,
  customModels: ReadonlySet<string>
): string {
  const key = modelKey ?? model
  if (!isModelKey(key) && !customModels.has(key)) {
    throw new UnknownModelError(key)
  }
  return key
}

/** Resolve a model's collection slug; resolved models always have one. */
function collectionFor(slugs: Readonly<Record<string, string>>, model: string): string {
  const slug: string | undefined = slugs[model]
  if (slug === undefined) {
    throw new UnknownModelError(model)
  }
  return slug
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
 * Map a Payload document to a Better Auth row: `baId` becomes `id`, the
 * numeric Payload `id` is dropped, and `date` fields become `Date`
 * instances (matching the memory adapter's in-memory semantics). With
 * `select`, only the selected physical fields are kept. Storage drift (a
 * row without `baId`, an unparseable date) throws `AdapterOperationError`
 * here instead of reaching Better Auth as a malformed row.
 */
function toBaRow(
  dates: ReadonlySet<string>,
  model: string,
  doc: Record<string, unknown>,
  select?: readonly string[]
): Record<string, unknown> {
  const include = (field: string): boolean => select === undefined || select.includes(field)
  const row: Record<string, unknown> = {}
  if (include('id')) {
    if (typeof doc.baId !== 'string' || doc.baId === '') {
      throw new AdapterOperationError(`${model} row: missing baId`)
    }
    row.id = doc.baId
  }
  for (const [key, value] of Object.entries(doc)) {
    if (key === 'id' || key === 'baId' || !include(key)) {
      continue
    }
    if (isDateField(dates, model, key) && typeof value === 'string') {
      const date = new Date(value)
      if (Number.isNaN(date.getTime())) {
        throw new AdapterOperationError(`${model} row: ${key} is not a valid date`)
      }
      row[key] = date
      continue
    }
    row[key] = value
  }
  return row
}

/**
 * Narrow Better Auth input to a record, then map it to Payload data: `id`
 * becomes `baId` on create (dropped on update), Payload-owned timestamps
 * are dropped, and `Date` instances become ISO strings.
 */
function toPayloadData(value: unknown, options: { forCreate: boolean }): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new AdapterOperationError('write: expected a data object')
  }
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) {
    if (key === 'id') {
      if (options.forCreate) {
        out.baId = entry
      }
      continue
    }
    if (key === 'createdAt' || key === 'updatedAt') {
      continue
    }
    out[key] = entry instanceof Date ? entry.toISOString() : entry
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
  slugs: Readonly<Record<string, string>>,
  dates: ReadonlySet<string>,
  depth: number,
  rows: Record<string, unknown>[],
  join: JoinConfig,
  customModels: ReadonlySet<string>
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
        const where: Where = {
          [baFieldToPayload(config.on.to)]: { equals: row[config.on.from] },
        }
        const found: unknown = await payload.find({
          collection: collectionFor(slugs, joinKey),
          where,
          limit: config.limit ?? joinLimitDefault,
          depth,
          pagination: false,
          overrideAccess: true,
        })
        const joined = narrowDocList(found, `join ${joinModel}`).map((doc) =>
          toBaRow(dates, joinKey, doc)
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
 */
export function createPayloadDatabaseAdapter(
  deps: PayloadDatabaseAdapterDeps
): AdapterFactory<BetterAuthOptions> {
  const customModels = deps.customModels ?? []
  const customFields = deps.customFields ?? {}
  const customNames = new Set(customModels.map((entry) => entry.model))
  const coreSlugs = resolveSlugs(defaultBetterAuthSlugs, deps.slugs)
  const slugs: Record<string, string> = {
    ...coreSlugs,
    ...Object.fromEntries(customModels.map((entry) => [entry.model, customModelSlug(entry)])),
  }
  assertUniqueSlugs(slugs, 'Better Auth adapter')
  const depth = deps.depth ?? 0

  return createAdapterFactory<BetterAuthOptions>({
    config: { adapterId: 'payload-auth-link', adapterName: 'Payload CMS' },
    adapter: (ctx: CreatorContext): CustomAdapter => {
      const { dateFields } = validateSchema(ctx, { fields: customFields, models: customModels })
      const payloadOf = (): Promise<Payload> => deps.getPayload()

      const findRawOne = async (
        collection: string,
        where: Where
      ): Promise<Record<string, unknown> | undefined> => {
        const payload = await payloadOf()
        const found: unknown = await payload.find({
          collection,
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
        translated: Where,
        postFilter: (row: Record<string, unknown>) => boolean
      ): Promise<Record<string, unknown> | undefined> => {
        const payload = await payloadOf()
        const found: unknown = await payload.find({
          collection: collectionFor(slugs, model),
          where: translated,
          limit: joinLimitDefault,
          depth,
          pagination: false,
          overrideAccess: true,
        })
        for (const doc of narrowDocList(found, `findRawExactOne ${model}`)) {
          if (postFilter(toBaRow(dateFields, model, doc))) {
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
        translated: Where,
        postFilter: (row: Record<string, unknown>) => boolean
      ): Promise<Array<string | number>> => {
        const payload = await payloadOf()
        const ids: Array<string | number> = []
        let page = 1
        for (;;) {
          const found: unknown = await payload.find({
            collection: collectionFor(slugs, model),
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
            if (postFilter(toBaRow(dateFields, model, doc))) {
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
        const { where, postFilter } = translateWhereClause(clauses)
        if (postFilter === undefined) {
          const found: unknown = await payload.find({
            collection: collectionFor(slugs, model),
            where,
            limit: 1,
            depth,
            pagination: false,
            overrideAccess: true,
          })
          let rows = narrowDocList(found, `findOne ${model}`).map((doc) =>
            toBaRow(dateFields, model, doc, select)
          )
          if (join) {
            rows = await applyJoin(payload, slugs, dateFields, depth, rows, join, customNames)
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
            collection: collectionFor(slugs, model),
            where,
            limit: pageSize,
            page,
            sort: 'id',
            depth,
            overrideAccess: true,
          })
          let rows = narrowDocList(found, `findOne ${model}`).map((doc) =>
            toBaRow(dateFields, model, doc, select)
          )
          if (join) {
            rows = await applyJoin(payload, slugs, dateFields, depth, rows, join, customNames)
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
          const key = resolveModel(modelKey, model, customNames)
          try {
            const payload = await payloadOf()
            const doc: unknown = await payload.create({
              collection: collectionFor(slugs, key),
              data: toPayloadData(data, { forCreate: true }),
              overrideAccess: true,
            })
            return asModelRow<T>(toBaRow(dateFields, key, narrowDoc(doc, `create ${key}`), select))
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
          const key = resolveModel(modelKey, model, customNames)
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
          const key = resolveModel(modelKey, model, customNames)
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(where ?? [])
            const skip = offset ?? 0
            const sort =
              sortBy === undefined
                ? undefined
                : `${sortBy.direction === 'desc' ? '-' : ''}${baFieldToPayload(sortBy.field)}`
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
                  collection: collectionFor(slugs, key),
                  where: translated,
                  limit: pageSize,
                  page,
                  ...(sort !== undefined ? { sort } : { sort: 'id' }),
                  depth,
                  overrideAccess: true,
                })
                let rows = narrowDocList(found, `findMany ${key}`).map((doc) =>
                  toBaRow(dateFields, key, doc, select)
                )
                if (join) {
                  rows = await applyJoin(payload, slugs, dateFields, depth, rows, join, customNames)
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
              collection: collectionFor(slugs, key),
              where: translated,
              limit: skip + limit,
              ...(sort === undefined ? {} : { sort }),
              depth,
              pagination: false,
              overrideAccess: true,
            })
            let rows = narrowDocList(found, `findMany ${key}`).map((doc) =>
              toBaRow(dateFields, key, doc, select)
            )
            if (join) {
              rows = await applyJoin(payload, slugs, dateFields, depth, rows, join, customNames)
            }
            return asModelRow<T[]>(rows.slice(skip, skip + limit))
          } catch (error) {
            throw rethrowAsOperation(error, `findMany ${key}`)
          }
        },

        count: async ({ model, modelKey, where }): Promise<number> => {
          const key = resolveModel(modelKey, model, customNames)
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(where ?? [])
            if (!postFilter) {
              const counted: unknown = await payload.count({
                collection: collectionFor(slugs, key),
                where: translated,
                overrideAccess: true,
              })
              return narrowCount(counted, `count ${key}`)
            }
            let page = 1
            let total = 0
            for (;;) {
              const found: unknown = await payload.find({
                collection: collectionFor(slugs, key),
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
                .map((doc) => toBaRow(dateFields, key, doc))
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
          const key = resolveModel(modelKey, model, customNames)
          if (where.length === 0) {
            return null
          }
          try {
            const { where: translated, postFilter } = translateWhereClause(where)
            const existing = postFilter
              ? await findRawExactOne(key, translated, postFilter)
              : await findRawOne(collectionFor(slugs, key), translated)
            if (!existing) {
              return null
            }
            const payload = await payloadOf()
            const doc: unknown = await payload.update({
              collection: collectionFor(slugs, key),
              id: readPayloadId(existing, `update ${key}`),
              data: toPayloadData(update, { forCreate: false }),
              overrideAccess: true,
            })
            return asModelRow<T | null>(toBaRow(dateFields, key, narrowDoc(doc, `update ${key}`)))
          } catch (error) {
            throw rethrowAsOperation(error, `update ${key}`)
          }
        },

        updateMany: async ({ model, modelKey, where, update }): Promise<number> => {
          const key = resolveModel(modelKey, model, customNames)
          if (where.length === 0) {
            return 0
          }
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(where)
            const data = toPayloadData(update, { forCreate: false })
            if (postFilter) {
              const ids = await findExactIds(key, translated, postFilter)
              if (ids.length === 0) {
                return 0
              }
              const result: unknown = await payload.update({
                collection: collectionFor(slugs, key),
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
              collection: collectionFor(slugs, key),
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
          const key = resolveModel(modelKey, model, customNames)
          if (where.length === 0) {
            throw new AdapterOperationError(`delete ${key}: refusing empty where clause`)
          }
          try {
            const { where: translated, postFilter } = translateWhereClause(where)
            const existing = postFilter
              ? await findRawExactOne(key, translated, postFilter)
              : await findRawOne(collectionFor(slugs, key), translated)
            if (!existing) {
              return
            }
            const payload = await payloadOf()
            await payload.delete({
              collection: collectionFor(slugs, key),
              id: readPayloadId(existing, `delete ${key}`),
              overrideAccess: true,
            })
          } catch (error) {
            throw rethrowAsOperation(error, `delete ${key}`)
          }
        },

        deleteMany: async ({ model, modelKey, where }): Promise<number> => {
          const key = resolveModel(modelKey, model, customNames)
          if (where.length === 0) {
            throw new AdapterOperationError(`deleteMany ${key}: refusing empty where clause`)
          }
          try {
            const payload = await payloadOf()
            const { where: translated, postFilter } = translateWhereClause(where)
            if (postFilter) {
              const ids = await findExactIds(key, translated, postFilter)
              if (ids.length === 0) {
                return 0
              }
              const result: unknown = await payload.delete({
                collection: collectionFor(slugs, key),
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
              collection: collectionFor(slugs, key),
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
