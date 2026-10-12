import { describe, expect, it } from 'vitest'
import {
  defineProviderId,
  defineSessionId,
  defineUserId,
  parseCollectionMap,
  parseEmail,
  parseRole,
  registerUser,
  registerWithStore,
  validateStartupConfig,
  wellKnownProviderIds,
} from '../index.js'

describe('core entrypoint', () => {
  it('exposes the public API', () => {
    for (const fn of [
      defineProviderId,
      defineSessionId,
      defineUserId,
      parseCollectionMap,
      parseEmail,
      parseRole,
      registerUser,
      registerWithStore,
      validateStartupConfig,
    ]) {
      expect(fn).toBeTypeOf('function')
    }
    expect(wellKnownProviderIds.betterAuth).toBe('better-auth')
    expect(wellKnownProviderIds.authjs).toBe('authjs')
    expect(wellKnownProviderIds.workos).toBe('workos')
    expect(wellKnownProviderIds.clerk).toBe('clerk')
  })
})
