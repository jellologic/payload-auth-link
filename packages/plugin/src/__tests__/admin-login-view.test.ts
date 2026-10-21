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
  routes?: { readonly api?: string; readonly admin?: string },
  admin?: Record<string, unknown>
): {
  loginViewRegistered: boolean
  viewPath: string | undefined
  exportName: string | undefined
  clientProps: unknown
  forgotView: { exportName?: string | undefined; clientProps?: unknown } | undefined
  resetView: { exportName?: string | undefined; clientProps?: unknown } | undefined
} {
  const plugin = authLink(options)
  const config = plugin({
    collections: [],
    admin: { user: 'users', ...(admin ?? {}) },
    ...(routes === undefined ? {} : { routes }),
  } as never) as {
    admin?: {
      components?: {
        views?: Record<
          string,
          { Component?: { path?: string; exportName?: string; clientProps?: unknown } }
        >
      }
    }
  }
  const views = config.admin?.components?.views ?? {}
  const login = views['login']
  return {
    loginViewRegistered: login !== undefined,
    viewPath: login?.Component?.path,
    exportName: login?.Component?.exportName,
    clientProps: login?.Component?.clientProps,
    forgotView: shapeOf(views['forgot']),
    resetView: shapeOf(views['reset']),
  }
}

function shapeOf(
  view: { Component?: { exportName?: string; clientProps?: unknown } } | undefined
): { exportName?: string | undefined; clientProps?: unknown } | undefined {
  if (view === undefined) {
    return undefined
  }
  return { exportName: view.Component?.exportName, clientProps: view.Component?.clientProps }
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

  it('refuses admitAnonymous without a provider-owned-id port (issue #126)', () => {
    // Guests resolve to their own document only where the engine wrote
    // it (adopt mode); anything else refuses at config time.
    expect(() => buildConfigShape({ ...baseOptions(), admitAnonymous: true })).toThrow(
      /admitAnonymous/
    )
  })

  it('accepts admitAnonymous with a provider-owned-id port (issue #126)', () => {
    const { provider } = createStubProvider()
    const owned = { ...provider, providerUserIdsAreDocumentIds: true as const }
    expect(() =>
      buildConfigShape({ ...baseOptions(), providers: [owned], admitAnonymous: true })
    ).not.toThrow()
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
      // #157: no provider facts on the stub port — no alternative
      // methods are offered.
      magicLink: false,
      socialProviders: [],
    })
  })

  it('registers the provider forgot/reset views alongside it (issue #121)', () => {
    const shape = buildConfigShape({ ...baseOptions(), admin: { loginView: 'provider' } })
    expect(shape.forgotView).toEqual({
      exportName: 'ProviderForgotPasswordView',
      clientProps: {
        authBase: '/api/auth',
        forgotEndpoint: '/api/users/forgot-password',
        adminRoute: '/admin',
        resetRoute: '/admin/reset',
      },
    })
    expect(shape.resetView).toEqual({
      exportName: 'ProviderResetPasswordView',
      clientProps: {
        authBase: '/api/auth',
        resetEndpoint: '/api/users/reset-password',
        adminRoute: '/admin',
      },
    })
  })

  it('derives the view paths from Payload routes, the users slug, and plugin options', () => {
    const shape = buildConfigShape(
      {
        ...baseOptions(),
        usersCollection: 'operators',
        admin: { loginView: 'provider', signInPath: '/login', authBase: '/backend/auth' },
      },
      { api: '/backend', admin: '/cms' },
      { routes: { reset: '/password-reset' } }
    )
    expect(shape.clientProps).toEqual({
      authBase: '/backend/auth',
      loginEndpoint: '/backend/operators/login',
      adminRoute: '/cms',
      signInPath: '/login',
      magicLink: false,
      socialProviders: [],
    })
    // #121: the forgot view's email redirect follows the customized
    // `admin.routes.reset`, and both endpoints follow `routes.api` and
    // the users slug.
    expect(shape.forgotView?.clientProps).toEqual({
      authBase: '/backend/auth',
      forgotEndpoint: '/backend/operators/forgot-password',
      adminRoute: '/cms',
      resetRoute: '/cms/password-reset',
    })
    expect(shape.resetView?.clientProps).toEqual({
      authBase: '/backend/auth',
      resetEndpoint: '/backend/operators/reset-password',
      adminRoute: '/cms',
    })
  })

  it('passes the provider port’s magic-link and social facts into the login view (#157)', () => {
    // The alternative methods read the ENGINE's configuration off the
    // port — the same source the gates above read — never a separate
    // app-side list.
    const { provider } = createStubProvider()
    const withMethods = {
      ...provider,
      magicLinkEnabled: true as const,
      socialProviders: ['google', 'facebook'],
    }
    const shape = buildConfigShape({
      ...baseOptions(),
      providers: [withMethods],
      admin: { loginView: 'provider' },
    })
    expect(shape.clientProps).toMatchObject({
      magicLink: true,
      socialProviders: ['google', 'facebook'],
    })
    // The forgot/reset views stay method-free — they are not sign-in
    // surfaces.
    expect(shape.forgotView?.clientProps).not.toHaveProperty('magicLink')
    expect(shape.resetView?.clientProps).not.toHaveProperty('socialProviders')
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

  it('leaves Payload local login, forgot, and reset untouched by default', () => {
    const shape = buildConfigShape(baseOptions())
    expect(shape.loginViewRegistered).toBe(false)
    expect(shape.forgotView).toBeUndefined()
    expect(shape.resetView).toBeUndefined()
  })

  it('wires the option through wireOptions', () => {
    expect(
      wireOptions({ ...baseOptions(), admin: { loginView: 'provider' } }).adminProviderLoginView
    ).toBe(true)
    expect(wireOptions(baseOptions()).adminProviderLoginView).toBe(false)
  })
})
