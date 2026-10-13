import { useState, type FormEvent } from 'react'

/**
 * Auth.js email sign-in (Resend provider, delivery captured by the
 * dev mailbox): request a link/code, then enter the 6-digit code.
 * The code form navigates to the callback URL with the token in the
 * QUERY STRING — the only place the Auth.js email callback reads it.
 */
export function AuthJsEmailForm() {
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const requestLink = (event: FormEvent): void => {
    event.preventDefault()
    void (async () => {
      setPending(true)
      setError(null)
      try {
        const csrf = await fetch('/api/authjs/csrf', { credentials: 'same-origin' })
        const body = csrf.ok
          ? ((await csrf.json().catch(() => null)) as { csrfToken?: unknown } | null)
          : null
        if (typeof body?.csrfToken !== 'string') {
          setError('Sign-in failed')
          return
        }
        const response = await fetch('/api/authjs/signin/resend', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            csrfToken: body.csrfToken,
            email,
            callbackUrl: '/account',
          }),
        })
        if (response.ok) {
          setStatus('Magic link sent. Follow it from the dev mailbox, or enter its code below.')
        } else {
          setError('Sign-in failed')
        }
      } finally {
        setPending(false)
      }
    })()
  }

  const verifyCode = (event: FormEvent): void => {
    event.preventDefault()
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
