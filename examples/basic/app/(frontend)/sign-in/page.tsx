import Link from 'next/link'
import { Suspense } from 'react'
import { SignInForm } from './form'

export default function SignInPage() {
  return (
    <main>
      <h1>Sign in</h1>
      <Suspense fallback={<p>Loading…</p>}>
        <SignInForm />
      </Suspense>
      <p>
        <Link href="/sign-in-authjs">Sign in with Auth.js instead</Link>
      </p>
    </main>
  )
}
