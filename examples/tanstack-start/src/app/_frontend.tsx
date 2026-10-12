import { AuthLinkProvider } from '@payload-auth-link/react'
import { createSessionLoader } from '@payload-auth-link/tanstack-start'
import { createFileRoute, Outlet } from '@tanstack/react-router'
import { getSessionUser } from '../lib/session.js'
import { HydratedMarker } from './_frontend/-hydrated-marker.js'

export const Route = createFileRoute('/_frontend')({
  loader: createSessionLoader(() => getSessionUser()),
  component: FrontendLayout,
})

function FrontendLayout() {
  const { initialUser } = Route.useLoaderData()
  return (
    <AuthLinkProvider initialUser={initialUser}>
      <main>
        <Outlet />
      </main>
      <HydratedMarker />
    </AuthLinkProvider>
  )
}
