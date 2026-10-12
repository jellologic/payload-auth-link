'use client'

import { useRouter, useSearchParams } from 'next/navigation'
import { useState, type FormEvent } from 'react'
import { safeRedirectPath, useAuthLinkRefresh } from '@payload-auth-link/next'

type Mode = 'sign-in' | 'sign-up'

/**
 * Auth.js credentials form. Signup goes to the builder-owned
 * `/api/authjs-signup` route (Auth.js credentials store nothing
 * themselves); sign-in drives the Auth.js credentials callback the way
 * `signIn('credentials', { redirect: false })` does: fetch a CSRF token,
 * post the form body, follow the 302, and read the session cookie
 * Auth.js sets on the redirect response.
 */
export function AuthJsSignInForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const refreshAuth = useAuthLinkRefresh()
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
      if (mode === 'sign-up') {
        const signup = await fetch('/api/authjs-signup', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email, password }),
        })
        if (!signup.ok) {
          const body = (await signup.json().catch(() => null)) as { error?: unknown } | null
          setError(
            typeof body?.error === 'string' && body.error !== '' ? body.error : 'Sign-up failed'
          )
          return
        }
      }
      const csrf = await fetch('/api/authjs/csrf', { credentials: 'same-origin' })
      if (!csrf.ok) {
        setError('Sign-in failed')
        return
      }
      const { csrfToken } = (await csrf.json().catch(() => null)) as {
        csrfToken?: unknown
      } | null
      if (typeof csrfToken !== 'string') {
        setError('Sign-in failed')
        return
      }
      // The credentials callback always answers 302: to the callback
      // URL on success (session cookie attached), to the Auth.js
      // error/signin page with `?error=…` when `authorize` rejects. The
      // browser follows and jars the cookies; the final URL tells us
      // which path Auth.js took. (`json=true` is a next-auth v4
      // convention — @auth/core ignores it.)
      // The redirect param is attacker-controlled input: narrow it to an
      // in-app path before handing it to Auth.js or the router, so a
      // crafted link cannot bounce fresh logins off-site.
      const destination = safeRedirectPath(searchParams.get('redirect'))
      const params = new URLSearchParams({
        csrfToken,
        email,
        password,
        callbackUrl: destination,
      })
      const callback = await fetch('/api/authjs/callback/credentials', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: params,
      })
      if (!callback.ok || callback.url.includes('error=')) {
        setError('Sign-in failed')
        return
      }
      await refreshAuth()
      router.push(destination)
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
