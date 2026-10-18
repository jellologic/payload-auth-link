import { describe, expect, it } from 'vitest'
import {
  priorValue,
  sealLegacyValue,
  sealScopeOf,
  sealValue,
  unsealValue,
  type SealScope,
} from '../importer/host-writes.js'
import type { FieldWrite } from '../importer/types.js'

const secret = 'manifest-seal-test-secret'
const entry = (collection: string, id: string | number, field: string): string =>
  `${collection}\u0000${String(id)}\u0000${field}`
const run: SealScope = { databaseId: 'db-a', runId: 'run-1' }

function sealed(id: number, field: string, value: unknown, scope: SealScope = run): FieldWrite {
  return {
    collection: 'users',
    id,
    field,
    sealedBefore: sealValue(secret, JSON.stringify(value), entry('users', id, field), scope),
  }
}

describe('manifest sealing', () => {
  it('round-trips a captured value for its own entry and run', () => {
    expect(
      priorValue(secret, sealed(1, 'linkableEmail', 'a@test.dev'), undefined, { scope: run })
    ).toBe('a@test.dev')
    expect(sealed(1, 'linkable', true).sealedBefore).toMatch(/^v2\./)
  })

  it('refuses a sealed value moved onto another entry', () => {
    const fromOne = sealed(1, 'linkable', true)
    const moved: FieldWrite = { ...fromOne, id: 2 }
    expect(() => priorValue(secret, moved, undefined, { scope: run })).toThrow(/different entry/)
  })

  it('refuses the wrong secret', () => {
    expect(() =>
      priorValue('another-secret', sealed(1, 'linkable', true), undefined, { scope: run })
    ).toThrow(/PAYLOAD_SECRET/)
  })

  it('refuses to restore a field the kit never writes, sealed or plain', () => {
    expect(() => priorValue(secret, sealed(1, 'password', 'x'))).toThrow(/not a field this kit/)
    const plain: FieldWrite = {
      collection: 'users',
      id: 1,
      field: 'suspendedUntil',
      before: 'null',
    }
    expect(() => priorValue(secret, plain)).toThrow(/not a field this kit/)
  })
})

describe('run-bound seals (GHSA-xw9m-ph95-84rx)', () => {
  const roles = sealed(3, 'roles', ['admin'])

  it('a value sealed for one run does not open for another run or another database', () => {
    expect(() =>
      priorValue(secret, roles, undefined, { scope: { databaseId: 'db-a', runId: 'run-2' } })
    ).toThrow(/different database or run/)
    expect(() =>
      priorValue(secret, roles, undefined, { scope: { databaseId: 'db-b', runId: 'run-1' } })
    ).toThrow(/different database or run/)
  })

  it('a value copied into a manifest that names no run (an unsigned one) does not open', () => {
    expect(() => priorValue(secret, roles)).toThrow(/manifest names none/)
    expect(() => priorValue(secret, roles, undefined, { scope: null })).toThrow(
      /manifest names none/
    )
  })

  it('the scope is the manifest’s own database and run, or none', () => {
    expect(sealScopeOf({ databaseId: 'db-a', runId: 'run-1' })).toEqual(run)
    expect(sealScopeOf({ databaseId: 'db-a' })).toBeNull()
    expect(sealScopeOf({ databaseId: '', runId: 'run-1' })).toBeNull()
    expect(sealScopeOf({})).toBeNull()
  })

  it('legacy (0.5–0.8.0) entry-bound seals still open, in any scope', () => {
    const legacy: FieldWrite = {
      collection: 'users',
      id: 3,
      field: 'roles',
      sealedBefore: sealLegacyValue(secret, '["user"]', entry('users', 3, 'roles')),
    }
    expect(legacy.sealedBefore).toMatch(/^v1\./)
    expect(priorValue(secret, legacy)).toEqual(['user'])
    expect(priorValue(secret, legacy, undefined, { scope: run })).toEqual(['user'])
    // Still entry-bound.
    expect(() => priorValue(secret, { ...legacy, id: 4 })).toThrow(/different entry/)
    // The two schemes never open each other's values.
    const relabelled = `v1.${String(roles.sealedBefore).slice(3)}`
    expect(() => unsealValue(secret, relabelled, entry('users', 3, 'roles'), run)).toThrow(
      /different/
    )
  })

  it('refuses a value in no format the kit wrote', () => {
    expect(() => unsealValue(secret, 'plain', entry('users', 1, 'roles'), run)).toThrow(
      /not a sealed value/
    )
  })
})
