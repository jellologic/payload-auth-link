import { readDevSms } from '../../../lib/e2e-idp'

/**
 * LOCAL EXAMPLE ONLY: read the phone OTP codes the e2e variant's
 * `phoneNumber` plugin captured instead of texting them (no SMS
 * gateway; see lib/e2e-idp.ts). 404s in production — an outbox that
 * hands out live sign-in codes must never ship.
 */
export function GET(request: Request): Response {
  if (process.env.NODE_ENV === 'production') {
    return Response.json({ error: 'not found' }, { status: 404 })
  }
  const phoneNumber = new URL(request.url).searchParams.get('phoneNumber')
  if (phoneNumber === null || phoneNumber === '') {
    return Response.json({ error: 'phoneNumber is required' }, { status: 400 })
  }
  return Response.json({ messages: readDevSms(phoneNumber) })
}
