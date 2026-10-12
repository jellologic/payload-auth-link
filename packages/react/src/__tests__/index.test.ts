import { describe, expect, it } from 'vitest'
import { packageName } from '../index.js'

describe('react entrypoint', () => {
  it('identifies the package', () => {
    expect(packageName).toBe('@payload-auth-link/react')
  })
})
