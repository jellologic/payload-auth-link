import { createFileRoute } from '@tanstack/react-router'
import { clearDevMailbox, readDevMailbox } from '../lib/dev-mailbox.js'

/**
 * LOCAL EXAMPLE ONLY: read/clear the dev mailbox (magic links and OTP
 * codes captured in-process instead of emailed). 404s in production.
 */
export const Route = createFileRoute('/api/dev-mailbox')({
  server: {
    handlers: {
      GET: ({ request }: { request: Request }) => {
        if (process.env.NODE_ENV === 'production') {
          return Response.json({ error: 'not found' }, { status: 404 })
        }
        const email = new URL(request.url).searchParams.get('email') ?? undefined
        return Response.json({ messages: readDevMailbox(email) })
      },
      DELETE: () => {
        if (process.env.NODE_ENV === 'production') {
          return Response.json({ error: 'not found' }, { status: 404 })
        }
        clearDevMailbox()
        return Response.json({ cleared: true })
      },
    },
  },
})
