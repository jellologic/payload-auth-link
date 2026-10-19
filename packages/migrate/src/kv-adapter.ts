import { isRecord } from '@payload-auth-link/core'

/**
 * How the app's Payload key-value store is backed (issue #132). The
 * migration records its database identity, its runs, and the finalize
 * marker through `payload.kv`, and those records must live IN the
 * database they describe: a restore, branch, or clone of the database
 * stops carrying them otherwise, and eviction can lose the finalize
 * marker (the GHSA-xw9m binding semantics assume database durability).
 *
 * - `'none'` — no adapter configured: Payload's default, which is
 *   database-backed (the `payload-kv` collection / `payload_kv` table).
 * - `'database'` — `databaseKVAdapter()` (or equivalent) configured: it
 *   always ships the `kvCollection` it creates.
 * - `'external'` — any other adapter (Redis, …): the records live
 *   outside the database. Every kit command refuses this.
 */
export type KvAdapterKind = 'database' | 'external' | 'none'

export function kvAdapterOf(config: unknown): KvAdapterKind {
  if (!isRecord(config)) {
    return 'none'
  }
  const kv: unknown = config.kv
  if (kv === undefined || kv === null) {
    return 'none'
  }
  if (isRecord(kv) && isRecord(kv.kvCollection) && typeof kv.kvCollection.slug === 'string') {
    return 'database'
  }
  return 'external'
}
