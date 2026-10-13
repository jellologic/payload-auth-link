/**
 * Golden-DB upgrade test, MongoDB variant (B7). Env-gated: set
 * `GOLDEN_MONGO=1` to run (boots a per-run `mongodb-memory-server`
 * replset, same as the mongo e2e runner).
 *
 * Boot A creates the 0.1.1 shapes, so mongoose autoIndex builds the
 * unique `token_1` index. Boot B (current shapes) then demonstrates
 * the trap and the fix: the stale index is still there after boot
 * (Payload never drops indexes), and `reconcileAuthJsMongoIndexes`
 * backfills `key`, drops `token_1`, and builds `key_1`. Afterwards
 * the 0.2.0 behavior actually holds: the same token hash can exist
 * for two identifiers, and a duplicate pair is rejected.
 */
// @vitest-environment node
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createAuthJsCollections } from '../collections.js'
import { reconcileAuthJsMongoIndexes } from '../mongo-indexes.js'
import { createAuthJsCollections as createCollections011 } from './golden-0.1.1-collections.js'

const SECRET = 'golden-upgrade-mongo-secret!!!'
const users: CollectionConfig = { slug: 'users', auth: true, fields: [] }

let replset: MongoMemoryReplSet
let uri: string

async function boot(key: string, collections: CollectionConfig[]): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    db: mongooseAdapter({ url: uri, transactionOptions: false }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: [users, ...collections],
  })
  return getPayload({ config, key })
}

type IndexInfo = { name?: unknown; key?: unknown; unique?: unknown }

async function tokenIndexes(payload: Payload): Promise<readonly IndexInfo[]> {
  const connection = payload.db.connection as unknown as {
    db: { collection: (name: string) => { indexes: () => Promise<readonly IndexInfo[]> } }
  }
  return connection.db.collection('aj-verification-tokens').indexes()
}

function hasUniqueOn(indexes: readonly IndexInfo[], field: string): boolean {
  return indexes.some(
    (index) =>
      index.unique === true &&
      typeof index.key === 'object' &&
      index.key !== null &&
      field in index.key
  )
}

describe.skipIf(process.env.GOLDEN_MONGO !== '1')(
  'golden upgrade on MongoDB: 0.1.1 database on current code',
  () => {
    beforeAll(async () => {
      replset = await MongoMemoryReplSet.create({
        replSet: { count: 1, storageEngine: 'wiredTiger' },
      })
      uri = replset.getUri('pal_golden_mongo')
      const old = await boot('golden-mongo-old', createCollections011())
      await old.create({
        collection: 'aj-verification-tokens',
        overrideAccess: true,
        data: {
          identifier: 'golden-mongo@example.com',
          token: 'shared-otp-hash',
          expires: '2027-01-01T00:00:00.000Z',
        },
      })
      // autoIndex builds in the background; give token_1 time to exist.
      await new Promise((resolve) => setTimeout(resolve, 1500))
      expect(hasUniqueOn(await tokenIndexes(old), 'token')).toBe(true)
      await old.db.destroy?.()
    }, 300_000)

    afterAll(async () => {
      await replset.stop()
    })

    it('reconciles indexes: stale token dropped, key backfilled and unique', async () => {
      const current = await boot('golden-mongo-new', createAuthJsCollections())
      try {
        // The trap (B7): after a plain upgraded boot the stale unique
        // token index is STILL enforced — Payload never drops it.
        await new Promise((resolve) => setTimeout(resolve, 1500))
        expect(hasUniqueOn(await tokenIndexes(current), 'token')).toBe(true)

        const report = await reconcileAuthJsMongoIndexes(current)
        expect(report.status).toBe('reconciled')
        expect(report.droppedStaleTokenIndex).toBe(true)
        expect(report.backfilledKeys).toBe(1)
        expect(['created', 'present']).toContain(report.keyIndex)

        const after = await tokenIndexes(current)
        expect(hasUniqueOn(after, 'token')).toBe(false)
        expect(hasUniqueOn(after, 'key')).toBe(true)

        // Idempotent: a second run changes nothing.
        const again = await reconcileAuthJsMongoIndexes(current)
        expect(again).toMatchObject({
          status: 'reconciled',
          droppedStaleTokenIndex: false,
          backfilledKeys: 0,
          keyIndex: 'present',
        })

        // The same token hash now coexists across identifiers.
        const second = await current.create({
          collection: 'aj-verification-tokens',
          overrideAccess: true,
          data: {
            key: JSON.stringify(['other@example.com', 'shared-otp-hash']),
            identifier: 'other@example.com',
            token: 'shared-otp-hash',
            expires: '2027-01-01T00:00:00.000Z',
          },
        })
        expect(second).toMatchObject({ identifier: 'other@example.com' })
      } finally {
        await current.db.destroy?.()
      }
    }, 300_000)
  }
)
