// @vitest-environment happy-dom
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { formatIdentityLabel, IdentityRowLabel } from '../admin/IdentityRowLabel.js'

// The real `@payloadcms/ui` pulls CSS that Vitest cannot load, so the hook is
// mocked here; the component's contract with the real admin is proven by e2e.
const { rowData } = vi.hoisted(() => ({ rowData: { value: {} } }))
vi.mock('@payloadcms/ui', () => ({
  useRowLabel: () => ({ data: rowData.value, path: 'identities.0' }),
}))

describe('formatIdentityLabel', () => {
  it('renders provider and email', () => {
    expect(formatIdentityLabel({ providerId: 'stub', email: 'a@b.co' })).toBe('stub · a@b.co')
  })

  it('falls back for malformed rows', () => {
    expect(formatIdentityLabel({ nope: true })).toBe('identity')
    expect(formatIdentityLabel({ providerId: 'stub' })).toBe('stub')
    expect(formatIdentityLabel(null)).toBe('identity')
    expect(formatIdentityLabel('x')).toBe('identity')
  })
})

describe('IdentityRowLabel', () => {
  it('renders the hooked row', () => {
    rowData.value = { providerId: 'stub', email: 'a@b.co' }
    render(<IdentityRowLabel />)
    expect(screen.getByText('stub · a@b.co')).toBeDefined()
  })
})
