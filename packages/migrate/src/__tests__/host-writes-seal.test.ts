import { describe, expect, it } from 'vitest'
import { priorValue, sealValue } from '../importer/host-writes.js'
import type { FieldWrite } from '../importer/types.js'

const secret = 'manifest-seal-test-secret'
const entry = (collection: string, id: string | number, field: string): string =>
  `${collection}\u0000${String(id)}\u0000${field}`

function sealed(id: number, field: string, value: unknown): FieldWrite {
  return {
    collection: 'users',
    id,
    field,
    sealedBefore: sealValue(secret, JSON.stringify(value), entry('users', id, field)),
  }
}

describe('manifest sealing', () => {
  it('round-trips a captured value for its own entry', () => {
    expect(priorValue(secret, sealed(1, 'linkableEmail', 'a@test.dev'))).toBe('a@test.dev')
  })

  it('refuses a sealed value moved onto another entry', () => {
    const fromOne = sealed(1, 'linkable', true)
    const moved: FieldWrite = { ...fromOne, id: 2 }
    expect(() => priorValue(secret, moved)).toThrow(/different entry/)
  })

  it('refuses the wrong secret', () => {
    expect(() => priorValue('another-secret', sealed(1, 'linkable', true))).toThrow(
      /PAYLOAD_SECRET/
    )
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
