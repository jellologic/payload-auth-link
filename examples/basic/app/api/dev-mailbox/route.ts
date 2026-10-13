import { clearDevMailbox, readDevMailbox } from '../../../lib/dev-mailbox'

/**
 * LOCAL EXAMPLE ONLY: read/clear the dev mailbox (magic links and OTP
 * codes captured in-process instead of emailed). 404s in production —
 * a mailbox that hands out live sign-in links must never ship.
 */
export function GET(request: Request): Response {
  if (process.env.NODE_ENV === 'production') {
    return Response.json({ error: 'not found' }, { status: 404 })
  }
  const email = new URL(request.url).searchParams.get('email') ?? undefined
  return Response.json({ messages: readDevMailbox(email) })
}

export function DELETE(): Response {
  if (process.env.NODE_ENV === 'production') {
    return Response.json({ error: 'not found' }, { status: 404 })
  }
  clearDevMailbox()
  return Response.json({ cleared: true })
}
