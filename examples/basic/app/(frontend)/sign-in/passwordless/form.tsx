'use client'

import { useRouter } from 'next/navigation'
import { useState, type FormEvent } from 'react'
import { useAuthLinkRefresh } from '@payload-auth-link/next'
import { useAuthLink } from '@payload-auth-link/react'
import { authClient } from '../../../../lib/auth-client'

/**
 * Passwordless + guest sign-in (Better Auth `magicLink`, `emailOTP`,
 * `anonymous` plugins). Outgoing mail lands in the local dev mailbox
 * (`/api/dev-mailbox`); production deployments send real email.
 */
export function PasswordlessForm() {
  const router = useRouter()
  const refreshAuth = useAuthLinkRefresh()
  const { guest } = useAuthLink()
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const post = async (path: string, body: unknown): Promise<boolean> => {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!response.ok) {
      const parsed = (await response.json().catch(() => null)) as { message?: unknown } | null
      setError(
        typeof parsed?.message === 'string' && parsed.message !== ''
          ? parsed.message
          : 'Request failed'
      )
      return false
    }
    return true
  }

  const run = async (action: () => Promise<void>): Promise<void> => {
    setPending(true)
    setError(null)
    try {
      await action()
    } finally {
      setPending(false)
    }
  }

  const requestMagicLink = (event: FormEvent): void => {
    event.preventDefault()
    void run(async () => {
      if (await post('/api/auth/sign-in/magic-link', { email, callbackURL: '/account' })) {
        setStatus('Magic link sent. Open the dev mailbox to follow it.')
      }
    })
  }

  const requestOtp = (event: FormEvent): void => {
    event.preventDefault()
    void run(async () => {
      if (await post('/api/auth/email-otp/send-verification-otp', { email, type: 'sign-in' })) {
        setStatus('Code sent. Read it from the dev mailbox.')
      }
    })
  }

  const verifyOtp = (event: FormEvent): void => {
    event.preventDefault()
    void run(async () => {
      if (await post('/api/auth/sign-in/email-otp', { email, otp: code })) {
        await refreshAuth()
        router.push('/account')
      }
    })
  }

  const signInWithPasskey = (): void => {
    void run(async () => {
      const result = await authClient.signIn.passkey()
      if (result.error !== null) {
        setError('Passkey sign-in failed')
        return
      }
      await refreshAuth()
      router.push('/account')
    })
  }

  const continueAsGuest = (): void => {
    void run(async () => {
      if (await post('/api/auth/sign-in/anonymous', {})) {
        await refreshAuth()
        setStatus('You are browsing as a guest.')
      }
    })
  }

  return (
    <div>
      <label>
        Email
        <input
          name="email"
          type="email"
          required
          autoComplete="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />
      </label>
      <form onSubmit={requestMagicLink}>
        <button type="submit" disabled={pending}>
          Email me a sign-in link
        </button>
      </form>
      <form onSubmit={requestOtp}>
        <button type="submit" disabled={pending}>
          Send me a sign-in code
        </button>
      </form>
      <form onSubmit={verifyOtp}>
        <label>
          Sign-in code
          <input
            name="otp"
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
      <button type="button" disabled={pending} onClick={signInWithPasskey}>
        Sign in with a passkey
      </button>
      <button type="button" disabled={pending} onClick={continueAsGuest}>
        Continue as guest
      </button>
      {guest ? <p data-testid="guest-id">Guest: {guest.id}</p> : null}
      {status ? <p role="status">{status}</p> : null}
      {error ? <p role="alert">{error}</p> : null}
    </div>
  )
}
