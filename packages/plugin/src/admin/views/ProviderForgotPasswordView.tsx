'use client'

import React, { useState } from 'react'
import { Button } from '@payloadcms/ui'

/**
 * The provider-backed admin forgot-password view (issue #121): two forms.
 *
 * - **Provider reset request** posts to Better Auth's own
 *   request-password-reset endpoint (`${authBase}/request-password-reset`)
 *   with `redirectTo` pointed at the provider reset view, so the email
 *   link lands back in the admin panel (`/admin/reset?token=…`). The
 *   provider owns the ceremony — linked accounts never mint a local
 *   credential (GHSA-f4hj).
 * - **Break-glass local request** posts to Payload's own forgot-password
 *   endpoint for UNLINKED operator accounts; linked documents are
 *   refused there by design (GHSA-f4hj), with the refusal surfaced.
 *
 * Replaces Payload's built-in forgot screen when
 * `admin: { loginView: 'provider' }` — Payload renders it at
 * /admin/forgot via the import map
 * (`@payload-auth-link/plugin/admin#ProviderForgotPasswordView`).
 */
export type ProviderForgotPasswordViewProps = {
  /**
   * The app-relative auth base for provider requests (e.g. `/api/auth`).
   * Set by the plugin from its own wiring (`admin.authBase`).
   */
  readonly authBase: string
  /**
   * Payload's local forgot-password endpoint for the break-glass form —
   * `${routes.api}/${usersSlug}/forgot-password`. Set by the plugin from
   * the Payload config; defaults to `/api/users/forgot-password`.
   */
  readonly forgotEndpoint?: string | undefined
  /**
   * Payload's `routes.admin`, for the link back to the login view. Set
   * by the plugin; defaults to `/admin`.
   */
  readonly adminRoute?: string | undefined
  /**
   * The admin path the reset email's link opens — Payload's
   * `routes.admin` joined with `admin.routes.reset` (the provider reset
   * view's route). Set by the plugin; defaults to `/admin/reset`.
   */
  readonly resetRoute?: string | undefined
}

type ForgotFormProps = {
  readonly heading: string
  readonly note: string
  readonly endpoint: string
  readonly label: string
  readonly failure: (status: number) => string
  /** Extra JSON body fields sent beside `email` (the provider `redirectTo`). */
  readonly extraBody?: Readonly<Record<string, string>> | undefined
}

/**
 * The provider response: Better Auth answers `200` with a status flag
 * whether or not the address is known (enumeration safety), and so
 * does Payload's own forgot-password.
 */
function ForgotForm({ heading, note, endpoint, label, failure, extraBody }: ForgotFormProps) {
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState(false)
  const [busy, setBusy] = useState(false)

  const request = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, ...extraBody }),
      })
      if (response.ok) {
        // A 200 means the request stood, never that the address exists
        // — both engines answer uniformly to prevent enumeration.
        setSent(true)
        return
      }
      setError(failure(response.status))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Request failed')
    } finally {
      setBusy(false)
    }
  }

  if (sent) {
    return (
      <div className="provider-forgot__confirmation">
        <h2>{heading}</h2>
        <p>
          If the address belongs to an account, a reset link is on its way — follow it from this
          browser to finish the reset.
        </p>
      </div>
    )
  }

  return (
    <form onSubmit={(event) => void request(event)}>
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
      {error !== null && <div className="provider-forgot__error">{error}</div>}
      <Button disabled={busy} type="submit">
        {busy ? 'Sending…' : label}
      </Button>
    </form>
  )
}

const ProviderForgotPasswordView: React.FC<ProviderForgotPasswordViewProps> = ({
  authBase,
  forgotEndpoint = '/api/users/forgot-password',
  adminRoute = '/admin',
  resetRoute = '/admin/reset',
}) => (
  <div className="provider-forgot">
    <ForgotForm
      endpoint={`${authBase}/request-password-reset`}
      extraBody={{ redirectTo: resetRoute }}
      failure={(status) =>
        status === 429
          ? 'Too many reset requests — wait a moment and try again.'
          : `Reset request failed (${String(status)})`
      }
      heading="Provider password reset"
      label="Send reset email"
      note="Provider-linked accounts reset their password through the provider — the email link opens the admin reset page."
    />
    <p>
      Follow the email&apos;s link to reach <a href={resetRoute}>the admin password reset page</a>,
      or return to <a href={`${adminRoute}/login`}>the admin sign-in</a>.
    </p>
    <ForgotForm
      endpoint={forgotEndpoint}
      failure={(status) =>
        status === 401 || status === 403
          ? 'Request failed: the account may be provider-linked — use your identity provider instead.'
          : `Request failed (${String(status)})`
      }
      heading="Break-glass local reset request"
      label="Send local reset email"
      note="Unlinked operator accounts only."
    />
  </div>
)

export default ProviderForgotPasswordView
