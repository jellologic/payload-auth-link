'use client'

import React, { useState } from 'react'
import { Button } from '@payloadcms/ui'

/**
 * The provider-backed admin login view (issue #55): email+password
 * through Payload's own login endpoint — the break-glass local form
 * for UNLINKED operator accounts (0.7.0 refuses provider-linked
 * documents here by design, GHSA-f4hj) — plus a link to the
 * provider's own sign-in page for everyone else.
 *
 * Registered by the plugin when `admin: { loginView: 'provider' }` —
 * Payload renders it at /admin/login via the import map.
 */
export type ProviderLoginViewProps = {
  /**
   * The app-relative auth base for provider sign-in requests
   * (e.g. `/api/auth`). Set by the plugin from its own wiring.
   */
  readonly authBase: string
}

const ProviderLoginView: React.FC<ProviderLoginViewProps> = ({ authBase }) => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const localSignIn = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const response = await fetch('/api/users/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
      if (response.ok) {
        window.location.href = '/admin'
        return
      }
      setError(
        response.status === 401 || response.status === 403
          ? 'Sign-in failed: check the credentials, or use your identity provider.'
          : `Sign-in failed (${String(response.status)})`
      )
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="provider-login">
      <p>
        Admin sign-in runs through your identity provider.{' '}
        <a href={`${authBase}/sign-in`}>Sign in with your provider</a> and return here — this admin
        session will pick it up.
      </p>
      <form onSubmit={(event) => void localSignIn(event)}>
        <h2>Break-glass local sign-in</h2>
        <p>Unlinked operator accounts only.</p>
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
          {busy ? 'Signing in…' : 'Sign in locally'}
        </Button>
      </form>
    </div>
  )
}

export default ProviderLoginView
