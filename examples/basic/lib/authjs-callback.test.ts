import { describe, expect, it } from 'vitest'
import { isAuthJsFailureLanding } from './authjs-callback.js'

describe('isAuthJsFailureLanding', () => {
  it('reports Auth.js error and sign-in landings as failures', () => {
    expect(
      isAuthJsFailureLanding('http://localhost/api/authjs/error?error=CredentialsSignin')
    ).toBe(true)
    expect(
      isAuthJsFailureLanding('http://localhost/api/authjs/signin?error=CredentialsSignin')
    ).toBe(true)
  })

  it('reports success for a destination that itself carries error= (PAR-12)', () => {
    expect(isAuthJsFailureLanding('http://localhost/account?error=shown-by-the-app')).toBe(false)
    expect(isAuthJsFailureLanding('http://localhost/error-report')).toBe(false)
  })

  it('honors a custom basePath and fails closed on garbage', () => {
    expect(isAuthJsFailureLanding('http://localhost/auth/error', '/auth')).toBe(true)
    expect(isAuthJsFailureLanding('not a url')).toBe(true)
  })
})
