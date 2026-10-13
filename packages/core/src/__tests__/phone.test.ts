import { describe, expect, it } from 'vitest'
import { InvalidPhoneNumberError } from '../errors.js'
import { parsePhoneNumber } from '../phone.js'

describe('parsePhoneNumber', () => {
  it('accepts E.164 numbers and brands them', () => {
    for (const value of ['+14155550132', '+442071838750', '+61412345678']) {
      const result = parsePhoneNumber(value)
      expect(result.isOk()).toBe(true)
      if (result.isOk()) {
        expect(result.value).toBe(value)
      }
    }
  })

  it('rejects non-E.164 input', () => {
    for (const value of [
      '',
      '4155550132',
      '004415550132',
      '+0',
      '+1 415 555 0132',
      '+abc',
      42,
      null,
      undefined,
    ]) {
      const result = parsePhoneNumber(value)
      expect(result.isErr()).toBe(true)
      if (result.isErr()) {
        expect(result.error).toBeInstanceOf(InvalidPhoneNumberError)
        expect(result.error.code).toBe('INVALID_PHONE_NUMBER')
      }
    }
  })
})
