'use client'

import React, { useState } from 'react'
import { Button } from '@payloadcms/ui'

/**
 * The provider-backed admin reset-password view (issue #121): the form
 * the reset email's link opens.
 *
 * - **Provider reset** posts the token and the new password to Better
 *   Auth's own reset endpoint (`${authBase}/reset-password`) — the
 *   provider owns the ceremony, so linked accounts never mint a local
 *   credential (GHSA-f4hj).
 * - **Break-glass local reset** posts to Payload's own reset-password
 *   endpoint for UNLINKED operator accounts; linked documents are
 *   refused there by design (GHSA-f4hj), with the refusal surfaced.
 *
 * Better Auth's email link carries the token as a `?token=` query
 * parameter on `redirectTo`; the view reads it from there, falling
 * back to a `/reset/:token` path segment. Registered by the plugin
 * when `admin: { loginView: 'provider' }` — Payload renders it at
 * `/admin/reset` via the import map
 * (`@payload-auth-link/plugin/admin#ProviderResetPasswordView`).
 */
export type ProviderResetPasswordViewProps = {
  /**
   * The app-relative auth base for provider requests (e.g. `/api/auth`).
   * Set by the plugin from its own wiring (`admin.authBase`).
   */
  readonly authBase: string
  /**
   * Payload's local reset-password endpoint for the break-glass form —
   * `${routes.api}/${usersSlug}/reset-password`. Set by the plugin from
   * the Payload config; defaults to `/api/users/reset-password`.
   */
  readonly resetEndpoint?: string | undefined
  /**
   * Payload's `routes.admin`, for the forgot link when the token is
   * missing and the link back to the login view after success. Set by
   * the plugin; defaults to `/admin`.
   */
  readonly adminRoute?: string | undefined
}

/**
 * Read the reset token the way the two flows hand it over: Better
 * Auth's redirect appends `?token=…` to `redirectTo`; a `/reset/:token`
 * path segment is the fallback (manual navigation, or an email
 * template pointing at the path form). `null` when neither is present.
 */
export function readResetToken(adminRoute: string): string | null {
  let url: URL
  try {
    url = new URL(window.location.href)
  } catch {
    return null
  }
  const queryToken = url.searchParams.get('token')
  if (queryToken !== null && queryToken !== '') {
    return queryToken
  }
  const base = adminRoute.endsWith('/') ? adminRoute.slice(0, -1) : adminRoute
  if (!url.pathname.startsWith(base)) {
    return null
  }
  const segments = url.pathname
    .slice(base.length)
    .split('/')
    .filter((segment) => segment !== '')
  if (segments.length === 2 && segments[0] === 'reset') {
    const pathToken = segments[1]
    if (pathToken !== undefined && pathToken !== '') {
      return pathToken
    }
  }
  return null
}

const ProviderResetPasswordView: React.FC<ProviderResetPasswordViewProps> = ({
  authBase,
  resetEndpoint = '/api/users/reset-password',
  adminRoute = '/admin',
}) => {
  const [token] = useState(() => readResetToken(adminRoute))
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)

  if (token === null) {
    return (
      <div className="provider-reset">
        <h2>Password reset</h2>
        <p>
          This page needs the token from a reset email — request one from{' '}
          <a href={`${adminRoute}/forgot`}>the forgot-password page</a>.
        </p>
      </div>
    )
  }

  const reset = async (
    event: React.FormEvent,
    endpoint: string,
    body: Record<string, string>,
    failure: (status: number) => string
  ): Promise<void> => {
    event.preventDefault()
    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (response.ok) {
        setDone(true)
        return
      }
      setError(failure(response.status))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Reset failed')
    } finally {
      setBusy(false)
    }
  }

  if (done) {
    return (
      <div className="provider-reset__confirmation">
        <h2>Password updated</h2>
        <p>
          Sign in with the new password through{' '}
          <a href={`${adminRoute}/login`}>the admin sign-in</a>.
        </p>
      </div>
    )
  }

  return (
    <div className="provider-reset">
      <form
        onSubmit={(event) =>
          void reset(
            event,
            `${authBase}/reset-password`,
            { token, newPassword: password },
            (status) =>
              status === 400
                ? 'Reset failed: the link is invalid or has expired — request a new one.'
                : `Reset failed (${String(status)})`
          )
        }
      >
        <h2>Provider password reset</h2>
        <p>Provider-linked accounts set their new password through the provider.</p>
        <label>
          New password
          <input
            autoComplete="new-password"
            name="new-password"
            onChange={(event_) => setPassword(event_.target.value)}
            type="password"
            value={password}
          />
        </label>
        <label>
          Confirm new password
          <input
            autoComplete="new-password"
            name="confirm-password"
            onChange={(event_) => setConfirmPassword(event_.target.value)}
            type="password"
            value={confirmPassword}
          />
        </label>
        {error !== null && <div className="provider-reset__error">{error}</div>}
        <Button disabled={busy} type="submit">
          {busy ? 'Updating…' : 'Set new password'}
        </Button>
      </form>
      <form
        onSubmit={(event) =>
          void reset(event, resetEndpoint, { password, token }, (status) =>
            status === 401 || status === 403
              ? 'Reset failed: the link may be invalid or expired, or the account is provider-linked — use your identity provider.'
              : `Reset failed (${String(status)})`
          )
        }
      >
        <h2>Break-glass local reset</h2>
        <p>Unlinked operator accounts only.</p>
        <Button disabled={busy} type="submit">
          {busy ? 'Updating…' : 'Set password locally'}
        </Button>
      </form>
    </div>
  )
}

export default ProviderResetPasswordView
