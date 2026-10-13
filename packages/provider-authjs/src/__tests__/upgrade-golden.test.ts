/**
 * Golden-DB upgrade test (PLAN-UPGRADE-RESILIENCE Phase 0/2, B2/B6/B8).
 *
 * Boot A creates a file-backed SQLite database with the exact 0.1.1
 * Auth.js collection shapes (fixture generated from the release tag)
 * — verification tokens keyed by a unique `token`, no composite
 * `key` column. Boot B starts the CURRENT collections on that file
 * in dev-push mode: in 0.2.0 this hung on drizzle's data-loss prompt
 * and recreated the token table empty, because `key` was added as
 * NOT NULL. With `key` nullable-unique the seeded token must survive
 * and stay consumable through the adapter (which reads by
 * `(identifier, token)`, tolerating the NULL key). Boot C restarts
 * the old shapes push-off to prove rollback reads still work.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createAuthJsAdapter } from '../adapter.js'
import { createAuthJsCollections } from '../collections.js'
import { createAuthJsCollections as createCollections011 } from './golden-0.1.1-collections.js'

const SECRET = 'golden-upgrade-authjs-secret!!'
const users: CollectionConfig = { slug: 'users', auth: true, fields: [] }

const dir = mkdtempSync(join(tmpdir(), 'pal-golden-aj-'))
const dbUrl = `file:${join(dir, 'golden.db')}`

async function boot(key: string, collections: CollectionConfig[], push: boolean): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    db: sqliteAdapter({ client: { url: dbUrl }, push }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: [users, ...collections],
  })
  return getPayload({ config, key })
}

describe('golden upgrade: 0.1.1 database on current code (Auth.js)', () => {
  beforeAll(async () => {
    const old = await boot('golden-aj-old', createCollections011(), true)
    await old.create({
      collection: 'aj-verification-tokens',
      overrideAccess: true,
      data: {
        identifier: 'golden@example.com',
        token: 'golden-token-hash',
        expires: '2027-01-01T00:00:00.000Z',
      },
    })
    await old.create({
      collection: 'aj-users',
      overrideAccess: true,
      data: { auId: 'aj-user-golden', email: 'golden@example.com', name: 'Golden' },
    })
    await old.db.destroy?.()
  }, 120_000)

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('boots in push mode; the pre-0.2.0 token survives and is consumable', async () => {
    const current = await boot('golden-aj-new', createAuthJsCollections(), true)
    try {
      const tokens = await current.find({
        collection: 'aj-verification-tokens',
        overrideAccess: true,
      })
      expect(tokens.totalDocs).toBe(1)
      expect(tokens.docs[0]).toMatchObject({ identifier: 'golden@example.com' })

      const adapter = createAuthJsAdapter({ getPayload: () => Promise.resolve(current) })
      // The legacy row (key = NULL) is consumed by (identifier, token).
      const claimed = await adapter.useVerificationToken?.({
        identifier: 'golden@example.com',
        token: 'golden-token-hash',
      })
      expect(claimed).toMatchObject({ identifier: 'golden@example.com' })

      // New tokens write the composite key; duplicate token hashes for
      // different identifiers coexist (the 0.2.0 fix still holds).
      await adapter.createVerificationToken?.({
        identifier: 'one@example.com',
        token: '123456',
        expires: new Date('2027-01-01T00:00:00.000Z'),
      })
      await adapter.createVerificationToken?.({
        identifier: 'two@example.com',
        token: '123456',
        expires: new Date('2027-01-01T00:00:00.000Z'),
      })
      const after = await current.find({
        collection: 'aj-verification-tokens',
        overrideAccess: true,
      })
      expect(after.totalDocs).toBe(2)
    } finally {
      await current.db.destroy?.()
    }
  }, 120_000)

  it('rollback direction: 0.1.1 shapes read the upgraded DB with push off', async () => {
    const rolledBack = await boot('golden-aj-rollback', createCollections011(), false)
    try {
      const ajUsers = await rolledBack.find({ collection: 'aj-users', overrideAccess: true })
      expect(ajUsers.totalDocs).toBe(1)
      expect(ajUsers.docs[0]).toMatchObject({ auId: 'aj-user-golden' })
    } finally {
      await rolledBack.db.destroy?.()
    }
  }, 120_000)
})
