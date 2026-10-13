import {
  isNonEmptyString,
  isRecord,
  nullLogger,
  resolveSlugs,
  type LoggerPort,
} from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { verificationTokenKey } from './adapter.js'
import { defaultAuthJsSlugs, type AuthJsCollectionSlugs } from './collections.js'

/** Outcome of {@link reconcileAuthJsMongoIndexes}. */
export type MongoIndexReconcileReport = {
  /** `not-mongo` when the Payload adapter exposes no Mongo connection. */
  readonly status: 'not-mongo' | 'reconciled' | 'key-index-failed'
  /** True when the stale pre-0.2.0 unique `token` index was dropped. */
  readonly droppedStaleTokenIndex: boolean
  /** Legacy token rows that received their composite `key`. */
  readonly backfilledKeys: number
  /** State of the composite `key` unique index after reconciliation. */
  readonly keyIndex: 'present' | 'created' | 'failed' | 'not-applicable'
  /** Failure detail when `keyIndex` is `failed`. */
  readonly detail?: string | undefined
}

/** Options for {@link reconcileAuthJsMongoIndexes}. */
export type MongoIndexReconcileOptions = {
  /** Collection slug overrides, same shape as the adapter's. */
  readonly slugs?: Partial<AuthJsCollectionSlugs> | undefined
  /** Receives one warning per action taken; defaults to silent. */
  readonly logger?: LoggerPort | undefined
}

type IndexInfo = {
  readonly name?: unknown
  readonly key?: unknown
  readonly unique?: unknown
}

type MongoCollectionLike = {
  indexes: () => Promise<readonly IndexInfo[]>
  dropIndex: (name: string) => Promise<unknown>
  createIndex: (
    spec: Record<string, 1>,
    options: { unique: boolean; name: string }
  ) => Promise<unknown>
  find: (filter: Record<string, unknown>) => {
    toArray: () => Promise<readonly Record<string, unknown>[]>
  }
  updateOne: (filter: Record<string, unknown>, update: Record<string, unknown>) => Promise<unknown>
}

function mongoDb(payload: Payload): { collection: (name: string) => MongoCollectionLike } | null {
  const db: unknown = payload.db
  if (!isRecord(db) || !isRecord(db.connection)) {
    return null
  }
  const native: unknown = db.connection.db
  if (!isRecord(native) || typeof native.collection !== 'function') {
    return null
  }
  return native as { collection: (name: string) => MongoCollectionLike }
}

function isSingleFieldIndex(index: IndexInfo, field: string): boolean {
  return isRecord(index.key) && Object.keys(index.key).length === 1 && index.key[field] === 1
}

/**
 * MongoDB upgrade reconciliation for the 0.2.0 verification-token
 * change (B7). Mongo cannot drift-crash on schema changes, so its
 * failure mode is silent: Payload's mongoose adapter auto-creates
 * indexes but never drops them, leaving the pre-0.2.0 unique `token`
 * index in force forever (the composite-key fix silently not
 * applying), while the new unique `key` index can fail to build over
 * legacy rows that lack the field. Run this once after upgrading a
 * Mongo deployment from 0.1.x (safe to run repeatedly):
 *
 * 1. backfills `key` on token rows that lack it, using the adapter's
 *    own composite-key encoding, so the unique build can succeed;
 * 2. drops the stale unique `token` index when present;
 * 3. ensures the unique `key` index exists and reports — loudly,
 *    via the returned report and the logger — when it cannot build.
 *
 * No-op with `status: 'not-mongo'` on SQL adapters, where Payload
 * manages indexes through migrations/push instead.
 */
export async function reconcileAuthJsMongoIndexes(
  payload: Payload,
  options?: MongoIndexReconcileOptions
): Promise<MongoIndexReconcileReport> {
  const logger = options?.logger ?? nullLogger()
  const db = mongoDb(payload)
  if (db === null) {
    return {
      status: 'not-mongo',
      droppedStaleTokenIndex: false,
      backfilledKeys: 0,
      keyIndex: 'not-applicable',
    }
  }
  const slugs = resolveSlugs(defaultAuthJsSlugs, options?.slugs)
  const collection = db.collection(slugs.verificationToken)

  const legacy = await collection
    .find({ $or: [{ key: { $exists: false } }, { key: null }] })
    .toArray()
  let backfilledKeys = 0
  for (const doc of legacy) {
    if (isNonEmptyString(doc.identifier) && isNonEmptyString(doc.token)) {
      await collection.updateOne(
        { _id: doc._id },
        { $set: { key: verificationTokenKey(doc.identifier, doc.token) } }
      )
      backfilledKeys += 1
    }
  }
  if (backfilledKeys > 0) {
    logger.warn('mongo upgrade: backfilled composite key on legacy verification tokens', {
      count: backfilledKeys,
    })
  }

  const indexes = await collection.indexes()
  let droppedStaleTokenIndex = false
  for (const index of indexes) {
    if (index.unique === true && isSingleFieldIndex(index, 'token')) {
      const name = isNonEmptyString(index.name) ? index.name : 'token_1'
      await collection.dropIndex(name)
      droppedStaleTokenIndex = true
      logger.warn('mongo upgrade: dropped stale unique token index', { index: name })
    }
  }

  const hasKeyIndex = indexes.some(
    (index) => index.unique === true && isSingleFieldIndex(index, 'key')
  )
  if (hasKeyIndex) {
    return { status: 'reconciled', droppedStaleTokenIndex, backfilledKeys, keyIndex: 'present' }
  }
  try {
    await collection.createIndex({ key: 1 }, { unique: true, name: 'key_1' })
    logger.warn('mongo upgrade: created unique composite key index', { index: 'key_1' })
    return { status: 'reconciled', droppedStaleTokenIndex, backfilledKeys, keyIndex: 'created' }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    logger.error('mongo upgrade: unique composite key index failed to build', { detail })
    return {
      status: 'key-index-failed',
      droppedStaleTokenIndex,
      backfilledKeys,
      keyIndex: 'failed',
      detail,
    }
  }
}
