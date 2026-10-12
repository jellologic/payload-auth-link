import { createServerRouteHandlers } from '@payload-auth-link/tanstack-start'
import { createFileRoute } from '@tanstack/react-router'
import { auth } from '../lib/auth.js'

export const Route = createFileRoute('/api/auth/$')({
  server: {
    handlers: createServerRouteHandlers((request) => auth.handler(request)),
  },
})
