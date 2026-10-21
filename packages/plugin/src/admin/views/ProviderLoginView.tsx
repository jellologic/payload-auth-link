'use client'

import React, { useState } from 'react'
import { Button } from '@payloadcms/ui'

/**
 * The provider-backed admin login view (issue #55): the alternative
 * methods section (issue #157, when the engine supports them), plus
 * two forms.
 *
 * - **Alternative methods** (issue #157): a "Continue with …" button
 *   per configured social provider — each navigates to Better Auth's
 *   social sign-in endpoint (`${authBase}/sign-in/social`) with the
 *   admin route as the `callbackURL` — and, with the magic-link
 *   plugin installed, an email form posting
 *   `${authBase}/sign-in/magic-link` (a "check your email" state
 *   follows). Rendered only when the engine actually supports a
 *   method: passwordless adopt-mode apps sign their users in here
 *   without any app-side view.
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
  /**
   * Whether the provider's engine supports magic-link sign-in (issue
   * #157: its magic-link plugin is installed) — renders the magic-link
   * email form. Set by the plugin from the provider port's
   * `magicLinkEnabled` fact; defaults to `false`.
   */
  readonly magicLink?: boolean | undefined
  /**
   * Social provider ids the engine registered (issue #157, e.g.
   * `'google'`) — one "Continue with …" button each. Set by the plugin
   * from the provider port's `socialProviders` fact; empty renders
   * none.
   */
  readonly socialProviders?: readonly string[] | undefined
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

/** Issue #157: the magic-link email form's props. */
type MagicLinkFormProps = {
  readonly authBase: string
  readonly adminRoute: string
}

/**
 * Issue #157: the magic-link sign-in form. Posts Better Auth's own
 * magic-link endpoint (`${authBase}/sign-in/magic-link`) with the
 * admin route as the `callbackURL`, so the emailed link lands back in
 * the admin panel with the session cookie set; a 200 swaps the form
 * for the "check your email" state. Bans and suspensions are enforced
 * by the engine's account-state plugin at session creation, so this is
 * purely a sign-in surface.
 */
const MagicLinkForm: React.FC<MagicLinkFormProps> = ({ authBase, adminRoute }) => {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const sendLink = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch(`${authBase}/sign-in/magic-link`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, callbackURL: adminRoute }),
      })
      if (response.ok) {
        // A 200 means the request stood — Better Auth answers
        // uniformly whether or not the address is known, so the sent
        // state leaks nothing about accounts.
        setSent(true)
        return
      }
      setError(`Sign-in failed (${String(response.status)})`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  if (sent) {
    return (
      <div className="provider-login__sent">
        Check your email — a sign-in link is on its way to <strong>{email}</strong>. Follow it from
        this browser to land back in the admin panel.
      </div>
    )
  }

  return (
    <form onSubmit={(event) => void sendLink(event)}>
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
      {error !== null && <div className="provider-login__error">{error}</div>}
      <Button disabled={busy} type="submit">
        {busy ? 'Sending…' : 'Continue'}
      </Button>
    </form>
  )
}

/** 'google' → 'Google' — the button label capitalizes the provider id. */
function socialProviderLabel(provider: string): string {
  return provider.charAt(0).toUpperCase() + provider.slice(1)
}

/**
 * Issue #157: Better Auth's social sign-in entry point for one
 * provider — navigating there runs the provider's OAuth dance and
 * returns to the admin route with the session cookie set.
 */
function socialSignInUrl(authBase: string, adminRoute: string, provider: string): string {
  return `${authBase}/sign-in/social?provider=${encodeURIComponent(provider)}&callbackURL=${encodeURIComponent(adminRoute)}`
}

const ProviderLoginView: React.FC<ProviderLoginViewProps> = ({
  authBase,
  loginEndpoint = '/api/users/login',
  adminRoute = '/admin',
  signInPath = '/sign-in',
  magicLink = false,
  socialProviders = [],
}) => {
  const alternativeMethods = magicLink || socialProviders.length > 0
  return (
    <div className="provider-login">
      {alternativeMethods && (
        <section className="provider-login__methods">
          <h2>Alternative sign-in methods</h2>
          {socialProviders.length > 0 && (
            <div className="provider-login__social">
              {socialProviders.map((provider) => (
                <Button
                  key={provider}
                  onClick={() => {
                    window.location.href = socialSignInUrl(authBase, adminRoute, provider)
                  }}
                  type="button"
                >
                  {`Continue with ${socialProviderLabel(provider)}`}
                </Button>
              ))}
            </div>
          )}
          {magicLink && <MagicLinkForm adminRoute={adminRoute} authBase={authBase} />}
        </section>
      )}
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
}

export default ProviderLoginView
