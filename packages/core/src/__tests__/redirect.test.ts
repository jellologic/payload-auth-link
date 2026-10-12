import { describe, expect, it } from 'vitest'
import { safeRedirectPath } from '../redirect.js'

describe('safeRedirectPath destination policy (PAR-11)', () => {
  it('falls back for the sign-in page, with or without a query or hash', () => {
    expect(safeRedirectPath('/sign-in')).toBe('/account')
    expect(safeRedirectPath('/sign-in?redirect=%2Faccount')).toBe('/account')
    expect(safeRedirectPath('/sign-in#top')).toBe('/account')
    expect(safeRedirectPath('/login', '/home', { signInPath: '/login' })).toBe('/home')
  })

  it('falls back for API destinations, never for look-alike pages', () => {
    expect(safeRedirectPath('/api')).toBe('/account')
    expect(safeRedirectPath('/api/users/me')).toBe('/account')
    expect(safeRedirectPath('/api?x=1')).toBe('/account')
    expect(safeRedirectPath('/apiary')).toBe('/apiary')
    expect(safeRedirectPath('/backend/x', '/', { apiPrefix: '/backend' })).toBe('/')
  })

  it('lets null disable only the sign-in rule', () => {
    expect(safeRedirectPath('/sign-in', '/', { signInPath: null })).toBe('/sign-in')
    expect(safeRedirectPath('/api/x', '/', { signInPath: null })).toBe('/')
  })

  it('keeps ordinary in-app paths byte for byte', () => {
    expect(safeRedirectPath('/account?tab=1&mode=edit')).toBe('/account?tab=1&mode=edit')
    expect(safeRedirectPath('/sign-in-authjs')).toBe('/sign-in-authjs')
  })
})
