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

function buildConfigShape(
  options: Parameters<typeof authLink>[0],
  routes?: { readonly api?: string; readonly admin?: string }
): {
  loginViewRegistered: boolean
  viewPath: string | undefined
  exportName: string | undefined
  clientProps: unknown
} {
  const plugin = authLink(options)
  const config = plugin({
    collections: [],
    admin: { user: 'users' },
    ...(routes === undefined ? {} : { routes }),
  } as never) as {
    admin?: {
      components?: {
        views?: {
          login?: { Component?: { path?: string; exportName?: string; clientProps?: unknown } }
        }
      }
    }
  }
  const login = config.admin?.components?.views?.login
  return {
    loginViewRegistered: login !== undefined,
    viewPath: login?.Component?.path,
    exportName: login?.Component?.exportName,
    clientProps: login?.Component?.clientProps,
  }
}

describe('provider-backed admin login view (issue #55)', () => {
  it('refuses loginView provider without a cookie-transport provider (#72)', () => {
    // The view's provider form posts to the cookie-transport
    // provider's sign-in endpoint; without one it would always 404.
    const { provider } = createStubProvider({ omitSessionCookie: true })
    expect(() =>
      buildConfigShape({
        ...baseOptions(),
        providers: [provider],
        admin: { loginView: 'provider' },
      })
    ).toThrow(/register a provider that mints cookie sessions/)
  })

  it('registers the custom login view when admin.loginView is provider', () => {
    const shape = buildConfigShape({ ...baseOptions(), admin: { loginView: 'provider' } })
    expect(shape.loginViewRegistered).toBe(true)
    expect(shape.viewPath).toBe('@payload-auth-link/plugin/admin')
    // #72: without the export name the view resolves to the module's
    // non-existent default export and never renders.
    expect(shape.exportName).toBe('ProviderLoginView')
    expect(shape.clientProps).toEqual({
      authBase: '/api/auth',
      loginEndpoint: '/api/users/login',
      adminRoute: '/admin',
      signInPath: '/sign-in',
    })
  })

  it('derives the view paths from Payload routes, the users slug, and plugin options', () => {
    const shape = buildConfigShape(
      {
        ...baseOptions(),
        usersCollection: 'operators',
        admin: { loginView: 'provider', signInPath: '/login', authBase: '/backend/auth' },
      },
      { api: '/backend', admin: '/cms' }
    )
    expect(shape.clientProps).toEqual({
      authBase: '/backend/auth',
      loginEndpoint: '/backend/operators/login',
      adminRoute: '/cms',
      signInPath: '/login',
    })
  })

  it('refuses non-app-relative view paths at wiring', () => {
    for (const bad of ['https://evil.example', '//evil.example', 'sign-in', '/a b']) {
      expect(() =>
        wireOptions({ ...baseOptions(), admin: { loginView: 'provider', signInPath: bad } })
      ).toThrow(/admin.signInPath/)
      expect(() =>
        wireOptions({ ...baseOptions(), admin: { loginView: 'provider', authBase: bad } })
      ).toThrow(/admin.authBase/)
    }
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
