'use client'

import Link from 'next/link'
import { useAuthLink, UserMenu } from '@payload-auth-link/react'

export default function AccountPage() {
  const { user, status } = useAuthLink()
  if (status === 'loading') {
    return (
      <main>
        <p>Loading…</p>
      </main>
    )
  }
  if (!user) {
    return (
      <main>
        <p>Signed out.</p>
        <Link href="/sign-in">Sign in</Link>
      </main>
    )
  }
  return (
    <main>
      <h1>Account</h1>
      <p data-testid="account-email">{user.email}</p>
      <p data-testid="account-roles">{user.roles.join(', ')}</p>
      <UserMenu signOutRedirectTo="/" />
    </main>
  )
}
