import { requireRoles } from '@payload-auth-link/next'
import { headers } from 'next/headers'
import { notFound, redirect } from 'next/navigation'
import { verifySession } from '../../../lib/session'

/**
 * Server-enforced MFA page (CAP-6): any signed-in user whose session
 * carries MFA proof may read it; a session without proof is bounced
 * to the account page to enroll (step-up), never shown the content.
 */
export default async function MfaOnlyPage() {
  const user = await requireRoles(await headers(), verifySession, {
    roles: ['user'],
    requireMfa: true,
    onAnonymous: () => redirect('/sign-in?redirect=/mfa-only'),
    onDenied: () => notFound(),
    onMfaRequired: () => redirect('/account?step-up=mfa'),
  })
  return (
    <main>
      <h1>MFA only</h1>
      <p data-testid="mfa-granted">Multi-factor content for {user.email}.</p>
    </main>
  )
}
