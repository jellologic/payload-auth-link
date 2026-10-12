import { describe, expect, it } from 'vitest'
import { packageName } from '../index.js'

describe('tanstack-start entrypoint', () => {
  it('identifies the package', () => {
    expect(packageName).toBe('@payload-auth-link/tanstack-start')
  })
})
