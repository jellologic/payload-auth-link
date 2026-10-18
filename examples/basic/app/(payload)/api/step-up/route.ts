import { NextResponse } from 'next/server'
import { authLinkServer } from '@payload-auth-link/plugin'
import { getPayload } from 'payload'
import configPromise from '@payload-config'

/**
 * Two-factor verification for the account page: verifies a TOTP code
 * through Better Auth itself (carrying the request's own cookies) and
 * hands the browser the session Better Auth rotated to. Whether that
 * session is MFA-proven is the PROVIDER's call, never this route's:
 * provider-better-auth relabels a step-up only with a factor enrolled
 * BEFORE the session began, so confirming an enrollment (or any code
 * the session itself just revealed) proves nothing — the user signs in
 * again with the factor to unlock MFA-gated access.
 *
 * Do not mint `createSessionFor(…, { mfaProof: true })` after a verify
 * like this one: a successful verify-totp is also how enrollment
 * completes, so the mint would turn a password-only self-enrollment
 * into MFA proof.
 */
export async function POST(request: Request): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { code?: unknown } | null
  const code = body?.code
  if (typeof code !== 'string' || code === '') {
    return NextResponse.json({ error: 'code required' }, { status: 400 })
  }
  const cookie = request.headers.get('cookie') ?? ''
  const origin = new URL(request.url).origin
  // Better Auth's CSRF check demands the browser's origin on mutating
  // requests — forward it, or the server-side verify fails with 400 no
  // matter how correct the code is.
  const originHeader = request.headers.get('origin')
  const verify = await fetch(`${origin}/api/auth/two-factor/verify-totp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie,
      ...(originHeader === null ? {} : { origin: originHeader }),
    },
    body: JSON.stringify({ code }),
  })
  if (!verify.ok) {
    return NextResponse.json({ error: 'That code did not verify' }, { status: verify.status })
  }
  // TOTP verification ROTATES the session: the live token is on the
  // verify response's Set-Cookie, not in the request's.
  const setCookies = verify.headers.getSetCookie()
  const rotated = setCookies.map((entry) => entry.split(';')[0]).join('; ')
  const payload = await getPayload({ config: configPromise })
  const session = await authLinkServer(payload).getSession(
    new Headers({ cookie: rotated || cookie })
  )
  if (session === null) {
    return NextResponse.json({ error: 'no live session' }, { status: 401 })
  }
  const assurance = session.assurance
  const mfa =
    typeof assurance === 'object' && assurance !== null && 'mfa' in assurance
      ? assurance.mfa === true
      : false
  const response = NextResponse.json({ ok: true, mfa })
  for (const entry of setCookies) {
    response.headers.append('set-cookie', entry)
  }
  return response
}
