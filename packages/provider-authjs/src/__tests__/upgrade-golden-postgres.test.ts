/**
 * Golden-DB upgrade test, Postgres variant (B6). Env-gated: runs only
 * when `GOLDEN_PG_URL` points at a disposable Postgres database, e.g.
 *
 *   docker run -d --name pal-golden-pg -e POSTGRES_PASSWORD=payload \
 *     -e POSTGRES_DB=golden -p 55432:5432 postgres:16
 *   GOLDEN_PG_URL=postgres://postgres:payload@localhost:55432/golden \
 *     bunx vitest run upgrade-golden-postgres
 *
 * The SQLite golden test proves the same shapes; this one proves the
 * Postgres-specific failure from B6 is gone: adding `key` in push
 * mode used to hang on the data-loss prompt and, in migrations mode,
 * `ADD COLUMN key NOT NULL` failed on the seeded row. The test drops
 * and recreates the public schema first — the database must be
 * disposable.
 */
import { postgresAdapter } from '@payloadcms/db-postgres'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAuthJsCollections } from '../collections.js'
import { createAuthJsCollections as createCollections011 } from './golden-0.1.1-collections.js'

const GOLDEN_PG_URL = process.env.GOLDEN_PG_URL
const SECRET = 'golden-upgrade-pg-secret!!!!!'
const users: CollectionConfig = { slug: 'users', auth: true, fields: [] }

async function resetSchema(): Promise<void> {
  // A leftover (possibly 0.2.0) schema would make the 0.1.1 push
  // boot hang on drizzle's downgrade data-loss prompt (B8), so the
  // run must start from a truly empty schema. The raw pool comes
  // from a throwaway push-off boot via drizzle's `$client` — `pg`
  // is not a direct dependency, so it cannot be imported here.
  const cleaner = await boot('golden-pg-reset', [], false)
  try {
    const pool = (
      cleaner.db.drizzle as unknown as { $client: { query: (q: string) => Promise<unknown> } }
    ).$client
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;')
  } finally {
    await cleaner.db.destroy?.()
  }
}

async function boot(key: string, collections: CollectionConfig[], push: boolean): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    db: postgresAdapter({ pool: { connectionString: GOLDEN_PG_URL }, push }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections: [users, ...collections],
  })
  return getPayload({ config, key })
}

describe.skipIf(GOLDEN_PG_URL === undefined)(
  'golden upgrade on Postgres: 0.1.1 database on current code',
  () => {
    beforeAll(async () => {
      await resetSchema()
      const old = await boot('golden-pg-old', createCollections011(), true)
      await old.create({
        collection: 'aj-verification-tokens',
        overrideAccess: true,
        data: {
          identifier: 'golden-pg@example.com',
          token: 'golden-pg-token',
          expires: '2027-01-01T00:00:00.000Z',
        },
      })
      await old.db.destroy?.()
    }, 180_000)

    it('boots in push mode with the seeded token intact (no prompt, no recreation)', async () => {
      const current = await boot('golden-pg-new', createAuthJsCollections(), true)
      try {
        const tokens = await current.find({
          collection: 'aj-verification-tokens',
          overrideAccess: true,
        })
        expect(tokens.totalDocs).toBe(1)
        expect(tokens.docs[0]).toMatchObject({ token: 'golden-pg-token' })
      } finally {
        await current.db.destroy?.()
      }
    }, 180_000)

    it('rollback direction: 0.1.1 shapes read the upgraded DB with push off', async () => {
      const rolledBack = await boot('golden-pg-rollback', createCollections011(), false)
      try {
        const tokens = await rolledBack.find({
          collection: 'aj-verification-tokens',
          overrideAccess: true,
        })
        expect(tokens.totalDocs).toBe(1)
      } finally {
        await rolledBack.db.destroy?.()
      }
    }, 180_000)
  }
)
