import type { CollectionSlug } from 'payload'
import { loadPayload } from '../../../lib/auth'

// The Better Auth users collection (`defaultBetterAuthSlugs.user`), as a
// literal: once `payload generate:types` has run, Payload's Local API
// only accepts the generated slug union, and `satisfies` checks the
// literal against it.
const baUsers = 'ba-users' satisfies CollectionSlug

/**
 * LOCAL EXAMPLE ONLY: stamps a Better Auth user verified immediately
 * after signup (there is no email delivery here). The plugin refuses
 * to provision or link unverified identities, so without a stamp the
 * example's credentials users would stay locked out — exactly like
 * the Auth.js side's signup route stamps `emailVerified`.
 *
 * Production builders verify out-of-band (email link, admin approval)
 * and never ship an endpoint that verifies arbitrary emails: this
 * route 404s in production.
 */
export async function POST(request: Request): Promise<Response> {
  if (process.env.NODE_ENV === 'production') {
    return Response.json({ error: 'not found' }, { status: 404 })
  }
  const body = (await request.json().catch(() => null)) as { email?: unknown } | null
  if (typeof body?.email !== 'string' || body.email === '') {
    return Response.json({ error: 'email is required' }, { status: 400 })
  }
  const payload = await loadPayload()
  const found = await payload.find({
    collection: baUsers,
    where: { email: { equals: body.email } },
    limit: 1,
    overrideAccess: true,
  })
  const row = found.docs[0] as { id: string | number } | undefined
  if (row === undefined) {
    return Response.json({ error: 'no such user' }, { status: 404 })
  }
  await payload.update({
    collection: baUsers,
    id: row.id,
    data: { emailVerified: true },
    overrideAccess: true,
  })
  return Response.json({ verified: true })
}
