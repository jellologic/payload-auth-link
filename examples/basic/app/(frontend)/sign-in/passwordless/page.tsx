import { Suspense } from 'react'
import { PasswordlessForm } from './form'

export default function PasswordlessSignInPage() {
  return (
    <main>
      <h1>Sign in without a password</h1>
      <Suspense fallback={<p>Loading…</p>}>
        <PasswordlessForm />
      </Suspense>
    </main>
  )
}
