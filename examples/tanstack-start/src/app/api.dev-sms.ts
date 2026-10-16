import { createFileRoute } from '@tanstack/react-router'
import { readDevSms } from '../lib/e2e-idp.js'

/**
 * LOCAL EXAMPLE ONLY: read the phone OTP codes the e2e variant's
 * `phoneNumber` plugin captured instead of texting them (no SMS
 * gateway; see lib/e2e-idp.ts). 404s in production.
 */
export const Route = createFileRoute('/api/dev-sms')({
  server: {
    handlers: {
      GET: ({ request }: { request: Request }) => {
        if (process.env.NODE_ENV === 'production') {
          return Response.json({ error: 'not found' }, { status: 404 })
        }
        const phoneNumber = new URL(request.url).searchParams.get('phoneNumber')
        if (phoneNumber === null || phoneNumber === '') {
          return Response.json({ error: 'phoneNumber is required' }, { status: 400 })
        }
        return Response.json({ messages: readDevSms(phoneNumber) })
      },
    },
  },
})
