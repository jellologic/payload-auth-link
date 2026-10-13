'use client'

import { useState, type FormEvent } from 'react'
import { authClient } from '../../../lib/auth-client'

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
      if (result.error !== null || result.data === null) {
        setError('Could not start two-factor enrollment')
        return
      }
      const { totpURI } = result.data
      const totpSecret =
        typeof totpURI === 'string' ? new URL(totpURI).searchParams.get('secret') : null
      setSecret(totpSecret)
      setStatus('Add the secret to your authenticator, then verify a code.')
    })
  }

  const verifyTwoFactor = (event: FormEvent): void => {
    event.preventDefault()
    void run(async () => {
      const result = await authClient.twoFactor.verifyTotp({ code })
      if (result.error !== null) {
        setError('That code did not verify')
        return
      }
      setStatus('Two-factor authentication is on.')
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
