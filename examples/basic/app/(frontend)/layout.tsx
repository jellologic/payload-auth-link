import type { ReactNode } from 'react'
import { AuthLinkServerProvider } from '@payload-auth-link/next'
import { verifySession } from '../../lib/session'
import { HydratedMarker } from './hydrated-marker'

export const metadata = {
  title: 'payload-auth-link example',
  description: 'Reference integration for the payload-auth-link plugin.',
}

export default function FrontendLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthLinkServerProvider verify={verifySession}>{children}</AuthLinkServerProvider>
        <HydratedMarker />
      </body>
    </html>
  )
}
