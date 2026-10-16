import { createHash, createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { authenticateManifest, signManifest } from '../importer/manifest-mac.js'
import type { ImportManifest } from '../importer/types.js'

const secret = 'manifest-mac-test-secret'

/** The 0.6.0 signing scheme, re-implemented: `finalized` left out. */
function legacyMac(key: string, manifest: ImportManifest): string {
  const canonical = (value: unknown): string => {
    if (Array.isArray(value)) {
      return `[${value.map((item) => canonical(item)).join(',')}]`
    }
    if (typeof value === 'object' && value !== null) {
      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      return `{${entries.map(([name, item]) => `${JSON.stringify(name)}:${canonical(item)}`).join(',')}}`
    }
    return JSON.stringify(value)
  }
  const body: Record<string, unknown> = { ...manifest, version: 3 }
  delete body['mac']
  delete body['finalized']
  const hmacKey = createHash('sha256')
    .update('payload-auth-link/migrate/manifest-mac/v1\u0000')
    .update(key)
    .digest()
  return `v1.${createHmac('sha256', hmacKey).update(canonical(body)).digest('base64url')}`
}

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
    expect(signed.mac).toMatch(/^v2\./)
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

  it('covers finalized: flipping it back to false fails the check', () => {
    const finalized = signManifest(secret, { ...base, finalized: true })
    expect(authenticateManifest(secret, finalized)).toBe('signed')
    expect(() => authenticateManifest(secret, { ...finalized, finalized: false })).toThrow(
      /integrity check/
    )
    expect(() =>
      authenticateManifest(secret, { ...signManifest(secret, base), finalized: true })
    ).toThrow(/integrity check/)
  })

  it('still verifies a 0.6.0 (v1.) MAC, as signed-legacy: its finalized flag is not covered', () => {
    const legacy: ImportManifest = { ...base, version: 3, mac: legacyMac(secret, base) }
    expect(authenticateManifest(secret, legacy)).toBe('signed-legacy')
    // Rows stay covered under the legacy scheme...
    expect(() =>
      authenticateManifest(secret, {
        ...legacy,
        created: [...legacy.created, { collection: 'jwks', id: 1, sourceKey: 'jwks:1' }],
      })
    ).toThrow(/integrity check/)
    // ...the finalized flag is the part it never covered.
    expect(authenticateManifest(secret, { ...legacy, finalized: true })).toBe('signed-legacy')
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
