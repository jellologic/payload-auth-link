import { safeRedirectPath, useAuthLinkRefreshStart } from '@payload-auth-link/tanstack-start'
import { useRouter } from '@tanstack/react-router'
import { useState, type FormEvent } from 'react'

type Mode = 'sign-in' | 'sign-up'

export function SignInForm({ redirect }: { redirect?: string }) {
  const router = useRouter()
  const refreshAuth = useAuthLinkRefreshStart()
  const [mode, setMode] = useState<Mode>('sign-in')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault()
    setPending(true)
    setError(null)
    try {
      const response = await fetch(
        mode === 'sign-in' ? '/api/auth/sign-in/email' : '/api/auth/sign-up/email',
        {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(
            mode === 'sign-in' ? { email, password } : { name: email, email, password }
          ),
        }
      )
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { message?: unknown } | null
        setError(
          typeof body?.message === 'string' && body.message !== '' ? body.message : 'Sign-in failed'
        )
        return
      }
      if (mode === 'sign-up') {
        // Local example only: the plugin provisions users only from
        // verified identities, and there is no email delivery here, so
        // the builder-owned dev route stamps the new user verified
        // (mirrors the Auth.js signup route's stamp).
        const stamped = await fetch('/api/dev-auto-verify', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email }),
        })
        if (!stamped.ok) {
          setError('Sign-up failed')
          return
        }
      }
      await refreshAuth()
      // The redirect param is attacker-controlled input: narrow it to an
      // in-app path so a crafted link cannot bounce fresh logins off-site.
      // Push the raw href (not `navigate`): `to` takes a path only and
      // `search` re-serializes with JSON quoting (`?tab=1` would become
      // `?tab="1"`), while history preserves the intercepted destination
      // byte for byte.
      router.history.push(safeRedirectPath(redirect))
    } finally {
      setPending(false)
    }
  }

  const toggle = () => {
    setMode(mode === 'sign-in' ? 'sign-up' : 'sign-in')
    setError(null)
  }

  return (
    <form
      onSubmit={(event) => {
        void submit(event)
      }}
    >
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
      <label>
        Password
        <input
          name="password"
          type="password"
          required
          minLength={8}
          autoComplete={mode === 'sign-in' ? 'current-password' : 'new-password'}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
      </label>
      {error ? <p role="alert">{error}</p> : null}
      <button type="submit" disabled={pending}>
        {mode === 'sign-in' ? 'Sign in' : 'Create account'}
      </button>
      <button type="button" onClick={toggle}>
        {mode === 'sign-in' ? 'Need an account? Sign up' : 'Have an account? Sign in'}
      </button>
    </form>
  )
}
