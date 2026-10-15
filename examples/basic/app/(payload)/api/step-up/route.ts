import { NextResponse } from 'next/server'
import { authLinkServer } from '@payload-auth-link/plugin'
import { getPayload } from 'payload'
import configPromise from '@payload-config'

/**
 * Step-up verification (the recorded-method integration pattern):
 * verifies a TOTP code through Better Auth itself — carrying the
 * request's own cookies, so the vouch is only as good as that check —
 * and, on success, mints a fresh session with the server-vouched MFA
 * proof (`createSessionFor({ mfaProof: true })`). The session then
 * records the method and MFA-gated access opens.
 *
 * MFA-gated apps need exactly this shape: enrollment alone proves
 * nothing; the server records the method only after IT verified the
 * challenge.
 */
export async function POST(request: Request): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { code?: unknown } | null
  const code = body?.code
  if (typeof code !== 'string' || code === '') {
    return NextResponse.json({ error: 'code required' }, { status: 400 })
  }
  const cookie = request.headers.get('cookie') ?? ''
  const origin = new URL(request.url).origin
  const verify = await fetch(`${origin}/api/auth/two-factor/verify-totp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ code }),
  })
  if (!verify.ok) {
    return NextResponse.json({ error: 'That code did not verify' }, { status: verify.status })
  }
  const payload = await getPayload({ config: configPromise })
  const server = authLinkServer(payload)
  const session = await server.getSession(new Headers({ cookie }))
  if (session === null) {
    return NextResponse.json({ error: 'no live session' }, { status: 401 })
  }
  const minted = await server.createSessionFor(session.id, {
    reason: 'step-up',
    mfaProof: true,
  })
  const response = NextResponse.json({ ok: true })
  if (minted.setCookie !== undefined) {
    response.headers.append('set-cookie', minted.setCookie)
  }
  return response
}
