import { requireRoles } from '@payload-auth-link/next'
import { headers } from 'next/headers'
import { notFound, redirect } from 'next/navigation'
import { verifySession } from '../../../lib/session'

/**
 * Role-gated page for the MFA-policy variant (`E2E_MFA_POLICY=1`, see
 * `payload.config.ts`): `auditor` is listed in
 * `policies.requireMfaForRoles` there, so a session without MFA proof
 * is projected WITHOUT the role and flagged `mfaRequired` —
 * `requireRoles` then takes the step-up branch (bounce to the account
 * page to enroll) instead of a flat denial. The default example has no
 * `auditor` role, so there everyone is denied.
 */
export default async function AuditorOnlyPage() {
  const user = await requireRoles(await headers(), verifySession, {
    roles: ['auditor'],
    onAnonymous: () => redirect('/sign-in?redirect=/auditor-only'),
    onDenied: () => notFound(),
    onMfaRequired: () => redirect('/account?step-up=mfa'),
  })
  return (
    <main>
      <h1>Auditor only</h1>
      <p data-testid="auditor-granted">Audit content for {user.email}.</p>
    </main>
  )
}
