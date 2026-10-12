import { describe, expect, it } from 'vitest'
import { ProviderError } from '../errors.js'
import { runProviderOperation, wellKnownProviderIds } from '../ports.js'

describe('runProviderOperation', () => {
  const providerId = wellKnownProviderIds.betterAuth

  it('narrows a successful call', async () => {
    const result = await runProviderOperation(
      providerId,
      'op',
      () => Promise.resolve(1),
      (value) => String(value)
    )
    expect(result.isOk()).toBe(true)
    if (result.isOk()) {
      expect(result.value).toBe('1')
    }
  })

  it('maps call rejections to ProviderError with the cause', async () => {
    const cause = new Error('sdk blew up')
    const result = await runProviderOperation(
      providerId,
      'op',
      () => Promise.reject(cause),
      (value) => value
    )
    expect(result.isErr()).toBe(true)
    if (result.isErr()) {
      expect(result.error).toBeInstanceOf(ProviderError)
      expect(result.error.providerId).toBe(providerId)
      expect(result.error.cause).toBe(cause)
    }
  })

  it('passes narrow ProviderErrors through and wraps foreign throws', async () => {
    const direct = new ProviderError(providerId, 'op')
    const passthrough = await runProviderOperation(
      providerId,
      'op',
      () => Promise.resolve(1),
      () => {
        throw direct
      }
    )
    expect(passthrough.isErr()).toBe(true)
    if (passthrough.isErr()) {
      expect(passthrough.error).toBe(direct)
    }
    const foreign = new TypeError('not a session')
    const wrapped = await runProviderOperation(
      providerId,
      'op',
      () => Promise.resolve(1),
      () => {
        throw foreign
      }
    )
    expect(wrapped.isErr()).toBe(true)
    if (wrapped.isErr()) {
      expect(wrapped.error).toBeInstanceOf(ProviderError)
      expect(wrapped.error.cause).toBe(foreign)
    }
  })
})
