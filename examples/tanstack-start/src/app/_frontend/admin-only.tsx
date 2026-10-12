import { createFileRoute } from '@tanstack/react-router'
import { getSessionUser, requireAdminUser } from '../../lib/session.js'

export const Route = createFileRoute('/_frontend/admin-only')({
  // Server-enforced before anything renders: the gate runs in a
  // server function (SSR and client navigation alike), so denied
  // callers never receive the content. A client-side gate would ship
  // the secret in the SSR payload and merely hide it.
  beforeLoad: () => requireAdminUser(),
  loader: async () => ({ user: await getSessionUser() }),
  component: AdminOnlyPage,
  // Same `admin-denied` marker the Next example renders from its
  // `not-found.tsx`: the shared e2e suite asserts the marker our code
  // renders, not either framework's default 404 text.
  notFoundComponent: AdminDenied,
})

function AdminDenied() {
  return <p data-testid="admin-denied">This page could not be found.</p>
}

function AdminOnlyPage() {
  const { user } = Route.useLoaderData()
  return (
    <>
      <h1>Admin only</h1>
      <p data-testid="admin-granted">Secret admin content for {user?.email}.</p>
    </>
  )
}
