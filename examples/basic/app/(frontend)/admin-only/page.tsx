import { requireRoles } from '@payload-auth-link/next'
import { headers } from 'next/headers'
import { notFound, redirect } from 'next/navigation'
import { verifySession } from '../../../lib/session'

/**
 * Server-enforced admin page. `requireRoles` runs on Node before anything
 * renders: anonymous visitors bounce to sign-in, authenticated
 * non-admins hit `notFound()`, and only admins ever receive the content.
 * A client-side gate (`RequireRoles`) would ship the secret in the RSC
 * payload and merely hide it — fine for UI chrome, never for content.
 */
export default async function AdminOnlyPage() {
  const user = await requireRoles(await headers(), verifySession, {
    roles: ['admin'],
    onAnonymous: () => redirect('/sign-in?redirect=/admin-only'),
    onDenied: () => notFound(),
  })
  return (
    <main>
      <h1>Admin only</h1>
      <p data-testid="admin-granted">Secret admin content for {user.email}.</p>
    </main>
  )
}
