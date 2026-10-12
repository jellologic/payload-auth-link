import * as web from '@payload-auth-link/web'
import { describe, expect, it } from 'vitest'
import * as adapter from '../index.js'

describe('tanstack-start entrypoint', () => {
  it('re-exports the whole web surface as the same bindings (ARCH-10)', () => {
    const webRuntime = Object.keys(web).filter((name) => name !== 'packageName')
    for (const name of webRuntime) {
      expect(adapter, name).toHaveProperty(name)
      expect((adapter as Record<string, unknown>)[name], name).toBe(
        (web as Record<string, unknown>)[name]
      )
    }
    // Its own identity wins over web's, and the shared surface is live.
    expect(adapter.packageName).toBe('@payload-auth-link/tanstack-start')
    expect(adapter.safeRedirectPath('//evil.example')).toBe('/account')
  })
})
