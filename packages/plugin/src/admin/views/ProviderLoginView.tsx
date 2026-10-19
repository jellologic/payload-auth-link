'use client'

import React, { useState } from 'react'
import { Button } from '@payloadcms/ui'

/**
 * The provider-backed admin login view (issue #55): two forms.
 *
 * - **Provider sign-in** posts to Better Auth's own email sign-in
 *   endpoint (`${authBase}/sign-in/email`), so provider-LINKED
 *   accounts — whose local password is refused on the Payload side
 *   (GHSA-f4hj) — can sign in to /admin here. Better Auth sets the
 *   same session cookie the middleware reads, so the admin session
 *   picks it up. Social-only users still sign in through the app's
 *   own sign-in page first; the cookie carries over.
 * - **Break-glass local sign-in** posts to Payload's own login
 *   endpoint for UNLINKED operator accounts (0.7.0 refuses
 *   provider-linked documents there by design, GHSA-f4hj).
 *
 * Registered by the plugin when `admin: { loginView: 'provider' }` —
 * Payload renders it at /admin/login via the import map
 * (`@payload-auth-link/plugin/admin#ProviderLoginView`). The same flag
 * registers the provider forgot/reset views (issue #121); the view
 * links to the forgot one below the sign-in forms.
 */
export type ProviderLoginViewProps = {
  /**
   * The app-relative auth base for provider sign-in requests
   * (e.g. `/api/auth`). Set by the plugin from its own wiring
   * (`admin.authBase`).
   */
  readonly authBase: string
  /**
   * Payload's local login endpoint for the break-glass form —
   * `${routes.api}/${usersSlug}/login`. Set by the plugin from the
   * Payload config; defaults to `/api/users/login`.
   */
  readonly loginEndpoint?: string | undefined
  /**
   * Where a successful sign-in lands — Payload's `routes.admin`. Set
   * by the plugin; defaults to `/admin`.
   */
  readonly adminRoute?: string | undefined
  /**
   * The app's own sign-in page, for social-only accounts. Set by the
   * plugin (`admin.signInPath`); defaults to `/sign-in`.
   */
  readonly signInPath?: string | undefined
}

type SignInFormProps = {
  readonly adminRoute: string
  readonly heading: string
  readonly note: string
  readonly endpoint: string
  readonly label: string
  readonly failure: (status: number) => string
}

/** The provider response body when Better Auth demands a second factor. */
function isTwoFactorRedirect(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<string, unknown>)['twoFactorRedirect'] === true
  )
}

const SignInForm: React.FC<SignInFormProps> = ({
  adminRoute,
  heading,
  note,
  endpoint,
  label,
  failure,
}) => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const signIn = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      if (response.ok) {
        // A 200 with `twoFactorRedirect` sets NO cookie — redirecting
        // here would just bounce back to the admin login.
        const body: unknown = await response.json().catch(() => null)
        if (isTwoFactorRedirect(body)) {
          setError(
            'Two-factor is required — finish signing in through the app sign-in page, then return here.'
          )
          return
        }
        window.location.href = adminRoute
        return
      }
      setError(failure(response.status))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={(event) => void signIn(event)}>
      <h2>{heading}</h2>
      <p>{note}</p>
      <label>
        Email
        <input
          autoComplete="email"
          name="email"
          onChange={(event_) => setEmail(event_.target.value)}
          type="email"
          value={email}
        />
      </label>
      <label>
        Password
        <input
          autoComplete="current-password"
          name="password"
          onChange={(event_) => setPassword(event_.target.value)}
          type="password"
          value={password}
        />
      </label>
      {error !== null && <div className="provider-login__error">{error}</div>}
      <Button disabled={busy} type="submit">
        {busy ? 'Signing in…' : label}
      </Button>
    </form>
  )
}

const ProviderLoginView: React.FC<ProviderLoginViewProps> = ({
  authBase,
  loginEndpoint = '/api/users/login',
  adminRoute = '/admin',
  signInPath = '/sign-in',
}) => (
  <div className="provider-login">
    <SignInForm
      adminRoute={adminRoute}
      endpoint={`${authBase}/sign-in/email`}
      failure={(status) =>
        status === 401
          ? 'Sign-in failed: check the credentials.'
          : `Sign-in failed (${String(status)})`
      }
      heading="Provider sign-in"
      label="Sign in with provider"
      note="Provider-linked accounts sign in through the provider."
    />
    <p>
      Social-only accounts (no provider password) sign in through the{' '}
      <a href={signInPath}>app sign-in page</a> and return here — the session cookie carries over.
    </p>
    <p>
      Forgot your password? <a href={`${adminRoute}/forgot`}>Reset it through the provider</a>.
    </p>
    <SignInForm
      adminRoute={adminRoute}
      endpoint={loginEndpoint}
      failure={(status) =>
        status === 401 || status === 403
          ? 'Sign-in failed: check the credentials, or use your identity provider.'
          : `Sign-in failed (${String(status)})`
      }
      heading="Break-glass local sign-in"
      label="Sign in locally"
      note="Unlinked operator accounts only."
    />
  </div>
)

export default ProviderLoginView
