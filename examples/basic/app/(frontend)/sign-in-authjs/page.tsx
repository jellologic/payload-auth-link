import Link from 'next/link'
import { Suspense } from 'react'
import { AuthJsSignInForm } from './form'

export default function AuthJsSignInPage() {
  return (
    <main>
      <h1>Sign in with Auth.js</h1>
      <Suspense fallback={<p>Loading…</p>}>
        <AuthJsSignInForm />
      </Suspense>
      <p>
        <Link href="/sign-in">Sign in with Better Auth instead</Link>
      </p>
    </main>
  )
}
