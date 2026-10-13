/**
 * Golden-DB upgrade test (PLAN-UPGRADE-RESILIENCE Phase 0/2, B1/B2/B8).
 *
 * Boot A creates a file-backed SQLite database with the exact 0.1.1
 * collection shapes (fixture generated from the release tag by
 * scripts/gen-golden-fixtures.mjs) and seeds rows. Boot B starts the
 * CURRENT collections on that same file in dev-push mode — the boot
 * that wedged real upgrades in 0.2.0 (`ba_users` table rebuild dying
 * on `is_anonymous`, `no such column: phone`). Boot C restarts the
 * OLD shapes with push off (production/migrations mode) to prove the
 * rollback direction still reads core rows on the upgraded schema.
 * Dev-push downgrades are destructive by Payload design and are
 * documented as unsupported instead of tested here.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type CollectionConfig, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthCollections } from '../collections.js'
import { createBetterAuthCollections as createCollections011 } from './golden-0.1.1-collections.js'

const SECRET = 'golden-upgrade-secret!!!!!!!!'

// The 0.1.1 plugin users shape (roles + identities only; phone and
// suspension columns arrived in 0.2.0 and must be added by push).
const users011: CollectionConfig = {
  slug: 'users',
  auth: { disableLocalStrategy: { enableFields: true, optionalPassword: true } },
  fields: [
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      required: true,
      options: [
        { label: 'admin', value: 'admin' },
        { label: 'user', value: 'user' },
      ],
      defaultValue: ['user'],
    },
    {
      name: 'identities',
      type: 'array',
      fields: [
        { name: 'providerId', type: 'text', required: true },
        { name: 'providerUserId', type: 'text', required: true },
        { name: 'email', type: 'email', required: true },
        { name: 'linkedAt', type: 'date', required: true },
      ],
    },
  ],
}

// The current plugin users additions (subset: the 0.2.0 columns).
const usersCurrent: CollectionConfig = {
  ...users011,
  fields: [
    ...(users011.fields ?? []),
    { name: 'phone', type: 'text', index: true },
    { name: 'suspendedUntil', type: 'date', index: true },
    { name: 'suspendReason', type: 'text' },
  ],
}

const dir = mkdtempSync(join(tmpdir(), 'pal-golden-ba-'))
const dbUrl = `file:${join(dir, 'golden.db')}`

async function boot(key: string, collections: CollectionConfig[], push: boolean): Promise<Payload> {
  const config = await buildConfig({
    secret: SECRET,
    db: sqliteAdapter({ client: { url: dbUrl }, push }),
    telemetry: false,
    logger: { options: { level: 'silent' } },
    collections,
  })
  return getPayload({ config, key })
}

async function shutdown(payload: Payload): Promise<void> {
  await payload.db.destroy?.()
}

describe('golden upgrade: 0.1.1 database on current code (Better Auth)', () => {
  beforeAll(async () => {
    const old = await boot('golden-ba-old', [users011, ...createCollections011()], true)
    await old.create({
      collection: 'ba-users',
      overrideAccess: true,
      data: {
        baId: 'ba-user-golden',
        email: 'golden@example.com',
        name: 'Golden User',
        emailVerified: true,
      },
    })
    await old.create({
      collection: 'users',
      overrideAccess: true,
      data: {
        email: 'golden@example.com',
        roles: ['admin'],
        identities: [
          {
            providerId: 'better-auth',
            providerUserId: 'ba-user-golden',
            email: 'golden@example.com',
            linkedAt: '2026-01-01T00:00:00.000Z',
          },
        ],
      },
    })
    await shutdown(old)
  }, 120_000)

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('boots in push mode with seeded rows intact and accepts new-shape writes', async () => {
    const current = await boot(
      'golden-ba-new',
      [
        usersCurrent,
        ...createBetterAuthCollections({
          // A 0.2.0-era plugin field addition (anonymous): additive
          // optional column, must not rebuild ba_users.
          customFields: { user: [{ name: 'isAnonymous', type: 'boolean' }] },
        }),
      ],
      true
    )
    try {
      const baUsers = await current.find({ collection: 'ba-users', overrideAccess: true })
      expect(baUsers.totalDocs).toBe(1)
      expect(baUsers.docs[0]).toMatchObject({ baId: 'ba-user-golden', name: 'Golden User' })

      const users = await current.find({ collection: 'users', overrideAccess: true })
      expect(users.totalDocs).toBe(1)
      expect(users.docs[0]).toMatchObject({ email: 'golden@example.com' })

      // BA's empty-name passwordless write must pass the restored
      // NOT NULL column via the custom validator.
      const created = await current.create({
        collection: 'ba-users',
        overrideAccess: true,
        data: { baId: 'ba-user-anon', email: 'anon@example.com', name: '', emailVerified: false },
      })
      expect(created).toMatchObject({ name: '' })

      // New additive columns are writable after push.
      const withPhone = await current.create({
        collection: 'users',
        overrideAccess: true,
        data: { email: 'phone@example.com', roles: ['user'], phone: '+15551234567' },
      })
      expect(withPhone).toMatchObject({ phone: '+15551234567' })
    } finally {
      await shutdown(current)
    }
  }, 120_000)

  it('rollback direction: 0.1.1 shapes read the upgraded DB with push off', async () => {
    const rolledBack = await boot(
      'golden-ba-rollback',
      [users011, ...createCollections011()],
      false
    )
    try {
      const baUsers = await rolledBack.find({ collection: 'ba-users', overrideAccess: true })
      expect(baUsers.totalDocs).toBe(2)
      const users = await rolledBack.find({ collection: 'users', overrideAccess: true })
      expect(users.totalDocs).toBe(2)
    } finally {
      await shutdown(rolledBack)
    }
  }, 120_000)
})
