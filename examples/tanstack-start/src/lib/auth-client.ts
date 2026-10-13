'use client'

import { passkeyClient } from '@better-auth/passkey/client'
import { twoFactorClient } from 'better-auth/client/plugins'
import { createAuthClient } from 'better-auth/react'

/**
 * Better Auth browser client for the flows whose ceremonies live in
 * the browser (WebAuthn, TOTP enrollment). Plain fetches cover the
 * rest of the example; this client exists for CAP-5/6 only.
 */
export const authClient = createAuthClient({
  plugins: [passkeyClient(), twoFactorClient()],
})
