import { nullLogger } from '@payload-auth-link/core'
import { describe, expect, it } from 'vitest'
import { authLink } from '../index.js'
import { wireOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

const ORIGIN = 'http://auth-link.test'

function baseOptions() {
  return {
    baseUrl: ORIGIN,
    roles: ['user', 'admin'],
    defaultRole: 'user',
    roleManagerRoles: ['admin'],
    providers: [createStubProvider().provider],
    logger: nullLogger(),
  }
}

function buildConfigShape(options: Parameters<typeof authLink>[0]): {
  loginViewRegistered: boolean
  viewPath: string | undefined
  clientProps: unknown
} {
  const plugin = authLink(options)
  const config = plugin({
    collections: [],
    admin: { user: 'users' },
  } as never) as {
    admin?: {
      components?: {
        views?: { login?: { Component?: { path?: string; clientProps?: unknown } } }
      }
    }
  }
  const login = config.admin?.components?.views?.login
  return {
    loginViewRegistered: login !== undefined,
    viewPath: login?.Component?.path,
    clientProps: login?.Component?.clientProps,
  }
}

describe('provider-backed admin login view (issue #55)', () => {
  it('registers the custom login view when admin.loginView is provider', () => {
    const shape = buildConfigShape({ ...baseOptions(), admin: { loginView: 'provider' } })
    expect(shape.loginViewRegistered).toBe(true)
    expect(shape.viewPath).toBe('@payload-auth-link/plugin/admin')
    expect(shape.clientProps).toEqual({ authBase: '/api/auth' })
  })

  it('leaves Payload local login untouched by default', () => {
    const shape = buildConfigShape(baseOptions())
    expect(shape.loginViewRegistered).toBe(false)
  })

  it('wires the option through wireOptions', () => {
    expect(
      wireOptions({ ...baseOptions(), admin: { loginView: 'provider' } }).adminProviderLoginView
    ).toBe(true)
    expect(wireOptions(baseOptions()).adminProviderLoginView).toBe(false)
  })
})
