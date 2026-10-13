import { createFileRoute } from '@tanstack/react-router'
import { PasswordlessForm } from './-sign-in-passwordless.form.js'

export const Route = createFileRoute('/_frontend/sign-in_/passwordless')({
  component: PasswordlessSignInPage,
})

function PasswordlessSignInPage() {
  return (
    <>
      <h1>Sign in without a password</h1>
      <PasswordlessForm />
    </>
  )
}
