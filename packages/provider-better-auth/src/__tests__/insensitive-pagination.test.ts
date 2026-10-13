/**
 * Adapter pagination under a case-insensitive `eq` (issue #18): the
 * contains-match decoys ahead of the real row used to eat the page,
 * so `findMany` returned empty results and `findOne` gave up inside
 * its fixed 100-row window. These tests plant more than `limit` (and
 * more than the 100-row joinLimitDefault) decoys BEFORE the real
 * match and require the exact row back.
 *
 * SQLite runs inline; Postgres and MongoDB run the same adapter code
 * through the six-combo e2e matrix, which signs in with case-shifted
 * emails against live BA sessions.
 */
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type Payload, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createBetterAuthEngine } from '../engine.js'

const ORIGIN = 'http://auth-link.test'
const SECRET = 'insensitive-pagination-secret!'

let config: SanitizedConfig
let payload: Payload
let latePayload: Payload | undefined

const DECOYS = 150

const engine = createBetterAuthEngine({
  getPayload: () => {
    if (!latePayload) {
      throw new Error('Payload not ready')
    }
    return Promise.resolve(latePayload)
  },
  options: {
    baseURL: ORIGIN,
    trustedOrigins: [ORIGIN],
    secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: false },
  },
})

async function adapter() {
  const ctx = await engine.auth.$context
  return ctx.adapter
}

describe('case-insensitive eq across page boundaries (issue #18)', () => {
  beforeAll(async () => {
    config = await buildConfig({
      secret: SECRET,
      serverURL: ORIGIN,
      db: sqliteAdapter({ client: { url: ':memory:' } }),
      telemetry: false,
      logger: { options: { level: 'silent' } },
      admin: { user: 'users' },
      collections: [{ slug: 'users', auth: true, fields: [] }, ...engine.collections],
      plugins: [],
    })
    payload = await getPayload({ config })
    latePayload = payload
    await engine.auth.$context
    // Decoy rows all CONTAIN the needle as a substring (so the
    // Payload `like` matches them) but never equal it
    // case-insensitively (so the post-filter drops them). They are
    // created BEFORE the real row, so a page-shaped read meets
    // decoys first.
    for (let index = 0; index < DECOYS; index += 1) {
      await payload.create({
        collection: 'ba-users',
        data: {
          baId: `decoy-${index}`,
          email: `${index}al@x.com`,
          name: `decoy ${index}`,
          emailVerified: true,
        },
        overrideAccess: true,
      })
    }
    await payload.create({
      collection: 'ba-users',
      data: {
        baId: 'real-one',
        email: 'AL@x.com',
        name: 'the real row',
        emailVerified: true,
      },
      overrideAccess: true,
    })
  }, 180_000)

  afterAll(async () => {
    await payload.db.destroy?.()
  })

  it('findMany returns the exact match despite a full page of decoys', async () => {
    const rows = await (
      await adapter()
    ).findMany<{ id: string }>({
      model: 'user',
      where: [{ field: 'email', value: 'al@x.com', operator: 'eq', mode: 'insensitive' }],
      limit: 5,
    })
    expect(rows).toHaveLength(1)
    expect(rows[0]?.id).toBe('real-one')
  })

  it('findMany with offset skips FILTERED rows, not decoys', async () => {
    // A second case-insensitive sibling so offset paging has content.
    await payload.create({
      collection: 'ba-users',
      data: {
        baId: 'real-two',
        email: 'aL@x.com',
        name: 'the second real row',
        emailVerified: true,
      },
      overrideAccess: true,
    })
    const page2 = await (
      await adapter()
    ).findMany<{ id: string }>({
      model: 'user',
      where: [{ field: 'email', value: 'al@x.com', operator: 'eq', mode: 'insensitive' }],
      limit: 1,
      offset: 1,
      sortBy: { field: 'email', direction: 'asc' },
    })
    expect(page2).toHaveLength(1)
    expect(page2[0]?.id).toBe('real-two')
  })

  it('findOne finds the exact match beyond the old fixed window', async () => {
    const row = await (
      await adapter()
    ).findOne<{ id: string }>({
      model: 'user',
      where: [{ field: 'email', value: 'al@x.com', operator: 'eq', mode: 'insensitive' }],
    })
    expect(row?.id).toBe('real-one')
  })
})
