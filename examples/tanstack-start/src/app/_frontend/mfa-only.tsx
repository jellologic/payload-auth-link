import { createFileRoute } from '@tanstack/react-router'
import { getSessionUser, requireMfaUser } from '../../lib/session.js'

export const Route = createFileRoute('/_frontend/mfa-only')({
  // Server-enforced MFA gate (CAP-6): denied callers never receive
  // the content; sessions without MFA proof bounce to /account.
  beforeLoad: () => requireMfaUser(),
  loader: async () => ({ user: await getSessionUser() }),
  component: MfaOnlyPage,
})

function MfaOnlyPage() {
  const { user } = Route.useLoaderData()
  return (
    <>
      <h1>MFA only</h1>
      <p data-testid="mfa-granted">Multi-factor content for {user?.email}.</p>
    </>
  )
}
