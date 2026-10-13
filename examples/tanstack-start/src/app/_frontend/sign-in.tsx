import { Link, createFileRoute } from '@tanstack/react-router'
import { SignInForm } from './-sign-in.form.js'

export const Route = createFileRoute('/_frontend/sign-in')({
  validateSearch: (search: Record<string, unknown>) => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
  }),
  component: SignInPage,
})

function SignInPage() {
  const { redirect } = Route.useSearch()
  return (
    <>
      <h1>Sign in</h1>
      <SignInForm redirect={redirect} />
      <p>
        <Link to="/sign-in/passwordless">Sign in without a password</Link>
      </p>
      <p>
        <Link to="/sign-in-authjs">Sign in with Auth.js instead</Link>
      </p>
    </>
  )
}
