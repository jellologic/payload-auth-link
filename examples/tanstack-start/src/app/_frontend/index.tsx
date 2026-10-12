import { Link, createFileRoute } from '@tanstack/react-router'
import { UserMenu } from '@payload-auth-link/react'

export const Route = createFileRoute('/_frontend/')({
  component: HomePage,
})

function HomePage() {
  return (
    <>
      <h1>payload-auth-link example</h1>
      <UserMenu />
      <nav>
        <Link to="/account">Account (protected)</Link> <Link to="/sign-in">Sign in</Link>
      </nav>
    </>
  )
}
