'use client'

import { useState, type FormEvent } from 'react'

/**
 * Auth.js email sign-in (Resend provider, delivery captured by the
 * dev mailbox): request a link/code, then enter the 6-digit code
 * from the mailbox. The code form posts the callback URL with the
 * token in the QUERY STRING — the only place the Auth.js email
 * callback reads it (recipe: `buildEmailOtpCallbackUrl`).
 */
export function AuthJsEmailForm() {
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const csrfToken = async (): Promise<string | null> => {
    const csrf = await fetch('/api/authjs/csrf', { credentials: 'same-origin' })
    if (!csrf.ok) {
      return null
    }
    const body = (await csrf.json().catch(() => null)) as { csrfToken?: unknown } | null
    return typeof body?.csrfToken === 'string' ? body.csrfToken : null
  }

  const requestLink = (event: FormEvent): void => {
    event.preventDefault()
    void (async () => {
      setPending(true)
      setError(null)
      try {
        const token = await csrfToken()
        if (token === null) {
          setError('Sign-in failed')
          return
        }
        const response = await fetch('/api/authjs/signin/resend', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            csrfToken: token,
            email,
            callbackUrl: '/account',
          }),
        })
        setStatus(
          response.ok
            ? 'Magic link sent. Follow it from the dev mailbox, or enter its code below.'
            : null
        )
        if (!response.ok) {
          setError('Sign-in failed')
        }
      } finally {
        setPending(false)
      }
    })()
  }

  const verifyCode = (event: FormEvent): void => {
    event.preventDefault()
    // Full navigation: the callback sets the session cookie on its
    // 302 to /account. Token travels in the query string by design.
    const params = new URLSearchParams({ token: code, email, callbackUrl: '/account' })
    window.location.assign(`/api/authjs/callback/resend?${params.toString()}`)
  }

  return (
    <div>
      <h2>Sign in with email</h2>
      <label>
        Email address
        <input
          name="authjs-email"
          type="email"
          required
          autoComplete="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />
      </label>
      <form onSubmit={requestLink}>
        <button type="submit" disabled={pending}>
          Email me a sign-in link
        </button>
      </form>
      <form onSubmit={verifyCode}>
        <label>
          Or enter the 6-digit code
          <input
            name="authjs-otp"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
        </label>
        <button type="submit" disabled={pending}>
          Verify code
        </button>
      </form>
      {status ? <p role="status">{status}</p> : null}
      {error ? <p role="alert">{error}</p> : null}
    </div>
  )
}
