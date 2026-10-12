import { describe, expect, it } from 'vitest'
import { InvalidRoleError } from '../errors.js'
import { parseRole } from '../roles.js'

describe('parseRole', () => {
  it('accepts lowercase slugs', () => {
    for (const value of ['admin', 'user', 'editor-2', 'a', 'x_y-z9']) {
      const result = parseRole(value)
      expect(result.isOk()).toBe(true)
      if (result.isOk()) {
        expect(result.value).toBe(value)
      }
    }
  })

  it('rejects empty, long, and malformed roles', () => {
    for (const value of ['', 'Admin', 'ADMIN', 'has space', 'dot.name', '-lead', 'x'.repeat(65)]) {
      const result = parseRole(value)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(InvalidRoleError)
        expect(result.error.code).toBe('INVALID_ROLE')
      }
    }
  })

  it('rejects non-strings', () => {
    for (const value of [undefined, null, 42, {}, ['admin']]) {
      expect(parseRole(value).isErr()).toBe(true)
    }
  })
})
