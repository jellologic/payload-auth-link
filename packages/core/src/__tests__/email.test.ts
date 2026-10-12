import { describe, expect, it } from 'vitest'
import { parseEmail } from '../email.js'
import { InvalidEmailError } from '../errors.js'

describe('parseEmail', () => {
  it('accepts valid emails and lowercases them', () => {
    const result = parseEmail('Dev@Example.COM')
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value).toBe('dev@example.com')
    }
  })

  it('rejects invalid emails', () => {
    for (const value of ['', 'not-an-email', 'a@b', '@example.com', 'x'.repeat(320) + '@e.com']) {
      const result = parseEmail(value)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(InvalidEmailError)
        expect(result.error.code).toBe('INVALID_EMAIL')
      }
    }
  })

  it('rejects non-strings', () => {
    for (const value of [undefined, null, 42, {}]) {
      expect(parseEmail(value).isErr()).toBe(true)
    }
  })
})
