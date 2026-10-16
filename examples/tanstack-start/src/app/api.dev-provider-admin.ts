import { defaultBetterAuthSlugs } from '@payload-auth-link/provider-better-auth'
import { createFileRoute } from '@tanstack/react-router'
import { loadPayload } from '../lib/auth.js'

/**
 * LOCAL EXAMPLE ONLY: grants a Better Auth user the provider-side
 * `admin` role that Better Auth's `admin()` plugin requires for its
 * operator endpoints (impersonation). The provider's user store is
 * closed to every API (Payload owns the users; the `ba-*` collections
 * are deny-all), so a fresh example database has no other way to get
 * its first impersonating operator.
 *
 * Production builders bootstrap operators out-of-band (`admin({
 * adminUserIds })`, a migration, a CLI) and never ship an endpoint
 * that grants roles: this route 404s in production.
 */
export const Route = createFileRoute('/api/dev-provider-admin')({
  server: {
    handlers: {
      POST: async ({ request }: { request: Request }) => {
        if (process.env.NODE_ENV === 'production') {
          return Response.json({ error: 'not found' }, { status: 404 })
        }
        const body = (await request.json().catch(() => null)) as { email?: unknown } | null
        if (typeof body?.email !== 'string' || body.email === '') {
          return Response.json({ error: 'email is required' }, { status: 400 })
        }
        const payload = await loadPayload()
        const found = await payload.find({
          collection: defaultBetterAuthSlugs.user,
          where: { email: { equals: body.email } },
          limit: 1,
          overrideAccess: true,
        })
        const row = found.docs[0] as { id: string | number } | undefined
        if (row === undefined) {
          return Response.json({ error: 'no such user' }, { status: 404 })
        }
        await payload.update({
          collection: defaultBetterAuthSlugs.user,
          id: row.id,
          data: { role: 'admin' },
          overrideAccess: true,
        })
        return Response.json({ role: 'admin' })
      },
    },
  },
})
