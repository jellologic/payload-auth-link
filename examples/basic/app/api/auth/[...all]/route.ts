import { createRouteHandlers } from '@payload-auth-link/next'
import { auth } from '../../../../lib/auth'

export const { GET, POST } = createRouteHandlers((request) => auth.handler(request))
