import { describe, expect, it } from 'vitest'
import { authenticateManifest, signManifest } from '../importer/manifest-mac.js'
import type { ImportManifest } from '../importer/types.js'

const secret = 'manifest-mac-test-secret'

const base: ImportManifest = {
  version: 2,
  kind: 'import',
  createdAt: '2026-10-16T00:00:00.000Z',
  sourceDatabase: 'postgres://***@db',
  options: { sessions: 'carry' },
  created: [{ collection: 'ba-users', id: 'ba-1', sourceKey: 'user:1' }],
  fieldWrites: [{ collection: 'users', id: 1, field: 'linkable', sealedBefore: 'v1.sealed' }],
  finalized: false,
  sourceCounts: { users: 1 },
  totals: { user: 1 },
}

describe('manifest integrity (GHSA-p76j-5qwx-rpwx follow-up)', () => {
  it('signs as version 3 and verifies under the same secret', () => {
    const signed = signManifest(secret, base)
    expect(signed.version).toBe(3)
    expect(signed.mac).toMatch(/^v1\./)
    expect(() => authenticateManifest(secret, signed)).not.toThrow()
  })

  it('verifies regardless of key order (a JSON round-trip)', () => {
    const signed = signManifest(secret, base)
    const reordered = JSON.parse(
      JSON.stringify(Object.fromEntries(Object.entries(signed).reverse()))
    ) as ImportManifest
    expect(() => authenticateManifest(secret, reordered)).not.toThrow()
  })

  it('refuses an added created row: an edited manifest cannot delete arbitrary rows', () => {
    const signed = signManifest(secret, base)
    const edited: ImportManifest = {
      ...signed,
      created: [...signed.created, { collection: 'users', id: 1, sourceKey: 'x' }],
    }
    expect(() => authenticateManifest(secret, edited)).toThrow(/integrity check/)
  })

  it('refuses an added plaintext field write: an edited manifest cannot set roles', () => {
    const signed = signManifest(secret, base)
    const edited: ImportManifest = {
      ...signed,
      fieldWrites: [
        ...signed.fieldWrites,
        { collection: 'users', id: 42, field: 'roles', before: '["admin"]' },
      ],
    }
    expect(() => authenticateManifest(secret, edited)).toThrow(/integrity check/)
  })

  it('refuses a downgrade to an unsigned version', () => {
    const signed: ImportManifest = { ...signManifest(secret, base), mac: undefined }
    expect(() => authenticateManifest(secret, { ...signed, version: 2 })).toThrow(
      /allow-unsigned-manifest/
    )
    expect(() => authenticateManifest(secret, { ...signed, version: 3 })).toThrow(/integrity check/)
  })

  it('refuses another secret', () => {
    expect(() => authenticateManifest('another-secret', signManifest(secret, base))).toThrow(
      /PAYLOAD_SECRET/
    )
  })

  it('leaves finalized outside the MAC (finalize loads no secret)', () => {
    const signed = signManifest(secret, base)
    expect(() => authenticateManifest(secret, { ...signed, finalized: true })).not.toThrow()
  })

  it('accepts a pre-0.6.0 manifest only with the explicit opt-in', () => {
    expect(() => authenticateManifest(secret, base)).toThrow(/allow-unsigned-manifest/)
    expect(() => authenticateManifest(secret, base, { allowUnsigned: true })).not.toThrow()
    const v1: ImportManifest = {
      ...base,
      version: 1,
      fieldWrites: [{ collection: 'users', id: 1, field: 'linkable', before: 'false' }],
    }
    expect(() => authenticateManifest(secret, v1, { allowUnsigned: true })).not.toThrow()
  })

  it('refuses plaintext values in a version-2 manifest even with the opt-in', () => {
    const edited: ImportManifest = {
      ...base,
      fieldWrites: [{ collection: 'users', id: 42, field: 'roles', before: '["admin"]' }],
    }
    expect(() => authenticateManifest(secret, edited, { allowUnsigned: true })).toThrow(/plaintext/)
  })
})
