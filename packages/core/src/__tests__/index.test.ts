import { describe, expect, it } from 'vitest'
import { parseRole, wellKnownProviderIds } from '../index.js'

describe('core entrypoint', () => {
  it('serves the canonical role constructor and the reserved provider ids', () => {
    expect(parseRole('admin').isOk()).toBe(true)
    expect(parseRole('Admin').isErr()).toBe(true)
    expect(wellKnownProviderIds).toEqual({
      betterAuth: 'better-auth',
      authjs: 'authjs',
      workos: 'workos',
      clerk: 'clerk',
    })
  })
})
