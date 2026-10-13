import { Link, createFileRoute } from '@tanstack/react-router'
import { AuthJsEmailForm } from './-sign-in-authjs-email.form.js'
import { AuthJsSignInForm } from './-sign-in-authjs.form.js'

export const Route = createFileRoute('/_frontend/sign-in-authjs')({
  validateSearch: (search: Record<string, unknown>) => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
  }),
  component: AuthJsSignInPage,
})

function AuthJsSignInPage() {
  const { redirect } = Route.useSearch()
  return (
    <>
      <h1>Sign in with Auth.js</h1>
      <AuthJsSignInForm redirect={redirect} />
      <AuthJsEmailForm />
      <p>
        <Link to="/sign-in">Sign in with Better Auth instead</Link>
      </p>
    </>
  )
}
