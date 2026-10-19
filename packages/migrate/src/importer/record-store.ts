import { isRecord } from '@payload-auth-link/core'
import type { Payload } from 'payload'

/**
 * The kit's own database-backed record store (issue #139): the
 * `payload-auth-link-migrations` collection the plugin declares, so the
 * database identity, the run records, and the finalize marker live IN
 * the database they describe — regardless of what `payload.config.kv`
 * is backed by (Redis, …). Restores, branches, and clones carry them;
 * eviction cannot touch them; the GHSA-xw9m binding semantics are
 * unchanged.
 *
 * Legacy databases recorded these in the app's `payload.kv` (the
 * payload-kv collection, 0.8.0–0.12.x). The first store access on such
 * a database copies every kit record (`payload-auth-link/migrate/*`)
 * into the collection — one bulk pass, flagged — and from then on the
 * collection is the only store consulted. Until the copy completes,
 * any failure refuses (fail closed, as the GHSA-crrr contract
 * requires); afterwards the app's KV adapter is irrelevant to the kit.
 *
 * A payload whose config declares no records collection (a fake, or an
 * app too old to ship the plugin) falls back to `payload.kv` directly,
 * preserving the pre-#139 behavior.
 */

const recordsSlug = 'payload-auth-link-migrations'
const migrationFlagKey = 'payload-auth-link/migrate/legacy-migrated'

export function recordsCollectionDeclared(payload: Payload): boolean {
  const collections: unknown = (payload.config as { collections?: unknown }).collections
  return (
    Array.isArray(collections) &&
    collections.some((entry) => isRecord(entry) && entry.slug === recordsSlug)
  )
}

/** The app's key-value store, reached structurally (Payload 3.6x+). */
export function legacyStore(payload: Payload): {
  readonly get: (key: string) => Promise<unknown>
  readonly set: (key: string, value: NonNullable<unknown>) => Promise<void>
  readonly keys: () => Promise<string[]>
} | null {
  const kv: unknown = (payload as { kv?: unknown }).kv
  if (
    isRecord(kv) &&
    typeof kv['get'] === 'function' &&
    typeof kv['set'] === 'function' &&
    typeof kv['keys'] === 'function'
  ) {
    return kv as unknown as {
      readonly get: (key: string) => Promise<unknown>
      readonly set: (key: string, value: NonNullable<unknown>) => Promise<void>
      readonly keys: () => Promise<string[]>
    }
  }
  return null
}

type RawRecord = { readonly id: unknown; readonly data: unknown }

async function rawFind(payload: Payload, key: string): Promise<RawRecord | null> {
  const found: unknown = await payload.find({
    collection: recordsSlug,
    where: { key: { equals: key } },
    limit: 1,
    depth: 0,
    pagination: false,
    overrideAccess: true,
  })
  const doc: unknown = (found as { docs?: unknown[] }).docs?.[0]
  return isRecord(doc) ? { id: doc.id, data: doc.data } : null
}

async function rawKeys(payload: Payload): Promise<string[]> {
  const found: unknown = await payload.find({
    collection: recordsSlug,
    limit: 10_000,
    depth: 0,
    pagination: false,
    overrideAccess: true,
  })
  const docs: unknown[] = (found as { docs?: unknown[] }).docs ?? []
  return docs
    .filter(isRecord)
    .map((doc) => doc.key)
    .filter((key): key is string => typeof key === 'string')
}

async function rawSet(payload: Payload, key: string, value: NonNullable<unknown>): Promise<void> {
  const existing = await rawFind(payload, key)
  if (existing !== null && (typeof existing.id === 'string' || typeof existing.id === 'number')) {
    await payload.update({
      collection: recordsSlug,
      id: existing.id,
      data: { data: value },
      overrideAccess: true,
    })
    return
  }
  await payload.create({
    collection: recordsSlug,
    data: { key, data: value },
    overrideAccess: true,
  })
}

const migrated = new WeakMap<object, Promise<void>>()

/**
 * Copy every kit record from the legacy `payload.kv` into the
 * collection, once per booted Payload (a memo guards concurrent
 * accesses; a failed copy stays failed — the command refuses and a
 * re-run starts fresh).
 */
function ensureLegacyMigrated(
  payload: Payload,
  legacy: NonNullable<ReturnType<typeof legacyStore>>
): Promise<void> {
  const existing = migrated.get(payload)
  if (existing !== undefined) {
    return existing
  }
  const task = (async () => {
    const flag = await rawFind(payload, migrationFlagKey)
    if (flag !== null) {
      return
    }
    const keys = await legacy.keys()
    for (const key of keys) {
      if (!key.startsWith('payload-auth-link/migrate/') || key === migrationFlagKey) {
        continue
      }
      const value: unknown = await legacy.get(key)
      if (value !== null && value !== undefined) {
        await rawSet(payload, key, value)
      }
    }
    await rawSet(payload, migrationFlagKey, { migratedAt: new Date().toISOString() })
  })()
  migrated.set(payload, task)
  task.catch(() => {})
  return task
}

/**
 * The kit's record store over the collection: `get` falls back to the
 * legacy `payload.kv` on a miss (copying the record over — write-
 * through), `keys` unions both, `set` writes the collection only.
 */
function collectionStore(payload: Payload): {
  readonly get: (key: string) => Promise<unknown>
  readonly set: (key: string, value: NonNullable<unknown>) => Promise<void>
  readonly keys: () => Promise<string[]>
} {
  const legacy = legacyStore(payload)
  const ready = legacy === null ? Promise.resolve() : ensureLegacyMigrated(payload, legacy)
  return {
    get: async (key) => {
      await ready
      const own = await rawFind(payload, key)
      if (own !== null && own.data !== undefined && own.data !== null) {
        return own.data
      }
      if (legacy === null) {
        return null
      }
      const legacyValue: unknown = await legacy.get(key)
      if (legacyValue === null || legacyValue === undefined) {
        return null
      }
      // Legacy record: copy it over so later reads (and restores and
      // clones) never depend on the app's KV adapter again.
      await rawSet(payload, key, legacyValue)
      return legacyValue
    },
    set: async (key, value) => {
      await ready
      await rawSet(payload, key, value)
    },
    keys: async () => {
      await ready
      const own = await rawKeys(payload)
      if (legacy === null) {
        return own
      }
      const legacyKeys = await legacy.keys()
      return [...new Set([...own, ...legacyKeys])]
    },
  }
}

/**
 * The kit's record store: the collection when the config declares it
 * (the plugin ships it), otherwise the app's `payload.kv` directly —
 * the pre-#139 behavior for payloads too old to declare the store.
 */
export function recordStoreFor(payload: Payload): {
  readonly get: (key: string) => Promise<unknown>
  readonly set: (key: string, value: NonNullable<unknown>) => Promise<void>
  readonly keys: () => Promise<string[]>
} | null {
  if (recordsCollectionDeclared(payload)) {
    return collectionStore(payload)
  }
  return legacyStore(payload)
}

export { recordsSlug }
