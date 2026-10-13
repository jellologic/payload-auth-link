import { Link, createFileRoute } from '@tanstack/react-router'
import { useAuthLink, UserMenu } from '@payload-auth-link/react'
import { AccountSecurity } from './-account-security.js'

export const Route = createFileRoute('/_frontend/account')({
  component: AccountPage,
})

function AccountPage() {
  const { user, status } = useAuthLink()
  if (status === 'loading') {
    return <p>Loading…</p>
  }
  if (!user) {
    return (
      <>
        <p>Signed out.</p>
        <Link to="/sign-in">Sign in</Link>
      </>
    )
  }
  return (
    <>
      <h1>Account</h1>
      <p data-testid="account-email">{user.email}</p>
      <p data-testid="account-roles">{user.roles.join(', ')}</p>
      <UserMenu signOutRedirectTo="/" />
      <AccountSecurity />
    </>
  )
}
