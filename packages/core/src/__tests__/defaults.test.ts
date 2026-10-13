import { afterEach, describe, expect, it, vi } from 'vitest'
import { consoleLogger, isSilentLogger, nullLogger } from '../defaults.js'

describe('consoleLogger (default plugin logger)', () => {
  const originals = { info: console.info, warn: console.warn, error: console.error }

  afterEach(() => {
    console.info = originals.info
    console.warn = originals.warn
    console.error = originals.error
  })

  it('writes info/warn/error to the matching console level, fields as JSON suffix', () => {
    const info = vi.fn()
    const warn = vi.fn()
    console.info = info
    console.warn = warn
    const logger = consoleLogger()
    logger.info('signed in', { providerId: 'stub' })
    logger.warn('provider session expired', { providerId: 'stub', channel: 'cookie' })
    expect(info).toHaveBeenCalledExactlyOnceWith('signed in {"providerId":"stub"}')
    expect(warn).toHaveBeenCalledExactlyOnceWith(
      'provider session expired {"providerId":"stub","channel":"cookie"}'
    )
  })

  it('keeps debug silent and child bounded', () => {
    const info = vi.fn()
    console.info = info
    const logger = consoleLogger()
    logger.debug('noisy trace')
    expect(info).not.toHaveBeenCalled()
    expect(logger.child({})).toBe(logger)
  })

  it('is not the silent logger; nullLogger is', () => {
    expect(isSilentLogger(consoleLogger())).toBe(false)
    expect(isSilentLogger(nullLogger())).toBe(true)
  })
})
