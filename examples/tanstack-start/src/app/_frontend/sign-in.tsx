import { Link, createFileRoute } from '@tanstack/react-router'
import { SignInForm } from './-sign-in.form.js'

export const Route = createFileRoute('/_frontend/sign-in')({
  // `redirect` is optional (absent, not `undefined`), so plain links to
  // this page need no `search` prop.
  validateSearch: (search: Record<string, unknown>): { redirect?: string } =>
    typeof search.redirect === 'string' ? { redirect: search.redirect } : {},
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
