'use client'

import { useState, type FormEvent } from 'react'
import { authClient } from '../../lib/auth-client.js'

/**
 * Account security settings (CAP-5/6): TOTP enrollment and passkey
 * registration against the Better Auth plugins. Enrollment state
 * lives provider-side; the plugin maps `twoFactorEnabled` to
 * session assurance, which `requireMfaForRoles` policies read.
 */
export function AccountSecurity() {
  const [password, setPassword] = useState('')
  const [secret, setSecret] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const run = async (action: () => Promise<void>): Promise<void> => {
    setPending(true)
    setError(null)
    try {
      await action()
    } finally {
      setPending(false)
    }
  }

  const enableTwoFactor = (event: FormEvent): void => {
    event.preventDefault()
    void run(async () => {
      const result = await authClient.twoFactor.enable({ password })
      // Enrollment answers a TOTP setup only for the `totp` method; the
      // `otp` method (email/SMS codes) carries no URI to show.
      if (result.error !== null || result.data === null || result.data.method !== 'totp') {
        setError('Could not start two-factor enrollment')
        return
      }
      const totpSecret = new URL(result.data.totpURI).searchParams.get('secret')
      setSecret(totpSecret)
      setStatus('Add the secret to your authenticator, then verify a code.')
    })
  }

  const verifyTwoFactor = (event: FormEvent): void => {
    event.preventDefault()
    void run(async () => {
      // Verify THROUGH the app's step-up route: it re-verifies the code
      // with Better Auth server-side and reports whether the provider
      // counted it as MFA proof for this session.
      const verify = await fetch('/api/step-up', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code }),
      })
      if (!verify.ok) {
        setError('That code did not verify')
        return
      }
      const result = (await verify.json().catch(() => null)) as { mfa?: unknown } | null
      // Confirming an enrollment proves nothing for THIS session (the
      // provider decides): MFA-gated access opens after the next sign-in
      // with the factor.
      setStatus(
        result?.mfa === true
          ? 'Two-factor authentication is on.'
          : 'Two-factor authentication is on. Sign in again with it to open MFA-protected pages.'
      )
    })
  }

  const addPasskey = (): void => {
    void run(async () => {
      const result = await authClient.passkey.addPasskey({ name: 'This device' })
      if (result.error !== null) {
        setError('Passkey registration failed')
        return
      }
      setStatus('Passkey added. You can sign in with it from the passwordless page.')
    })
  }

  return (
    <section>
      <h2>Security</h2>
      <form onSubmit={enableTwoFactor}>
        <label>
          Current password
          <input
            name="current-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <button type="submit" disabled={pending}>
          Set up two-factor authentication
        </button>
      </form>
      {secret !== null ? (
        <p data-testid="totp-secret">
          TOTP secret: <code>{secret}</code>
        </p>
      ) : null}
      <form onSubmit={verifyTwoFactor}>
        <label>
          Two-factor code
          <input
            name="totp-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
        </label>
        <button type="submit" disabled={pending}>
          Verify two-factor code
        </button>
      </form>
      <button type="button" disabled={pending} onClick={addPasskey}>
        Add a passkey
      </button>
      {status ? <p role="status">{status}</p> : null}
      {error ? <p role="alert">{error}</p> : null}
    </section>
  )
}
