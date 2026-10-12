import Link from 'next/link'
import { UserMenu } from '@payload-auth-link/react'

export default function HomePage() {
  return (
    <main>
      <h1>payload-auth-link example</h1>
      <UserMenu />
      <nav>
        <Link href="/account">Account (protected)</Link> <Link href="/sign-in">Sign in</Link>
      </nav>
    </main>
  )
}
