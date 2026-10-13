import Credentials from '@auth/core/providers/credentials'
import Resend from '@auth/core/providers/resend'
import {
  createAuthJsCredentials,
  createAuthJsEngine,
  emailOtpMaxAgeSeconds,
  emailOtpVerificationToken,
} from '@payload-auth-link/provider-authjs'
import { getPayload, type Payload } from 'payload'
import { exampleBaseURL } from './auth-base-url'
import { recordDevMail } from './dev-mailbox.js'

let cachedPayload: Promise<Payload> | undefined

/**
 * Payload loader for the Auth.js database adapter and credentials
 * service. Same acyclic dynamic-import pattern as `lib/auth.ts`.
 */
function loadPayload(): Promise<Payload> {
  cachedPayload ??= import('@payload-config').then((mod) => getPayload({ config: mod.default }))
  return cachedPayload
}

const credentials = createAuthJsCredentials({ getPayload: loadPayload })

export const authJsEngine = createAuthJsEngine({
  getPayload: loadPayload,
  baseURL: exampleBaseURL,
  options: {
    secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
    // Credentials REQUIRES the jwt strategy: Auth.js rejects
    // credentials with database sessions at config time, and the engine
    // fail-fasts that combination before Auth.js can 500.
    session: { strategy: 'jwt', maxAge: 3600 },
    providers: [
      // Email magic link + OTP (CAP-1/2 recipes), delivery captured
      // by the local dev mailbox — see the Next example's notes.
      Resend({
        apiKey: 'dev-mailbox-only',
        from: 'sign-in@example.com',
        maxAge: emailOtpMaxAgeSeconds,
        generateVerificationToken: emailOtpVerificationToken,
        sendVerificationRequest: ({ identifier, url, token }) => {
          recordDevMail({ kind: 'magic-link', email: identifier, url })
          recordDevMail({ kind: 'email-otp', email: identifier, code: token })
          return Promise.resolve()
        },
      }),
      Credentials({
        credentials: {
          email: { label: 'Email', type: 'email' },
          password: { label: 'Password', type: 'password' },
        },
        authorize: (candidate) => credentials.authorize(candidate),
      }),
    ],
  },
})

export const {
  provider: authJsProvider,
  collections: authJsCollections,
  handleRequest: handleAuthJsRequest,
} = authJsEngine

/**
 * Builder-owned signup: Auth.js credentials store nothing themselves,
 * so registration is an explicit service call. Verification is stamped
 * by builder policy (see the signup route).
 */
export const registerAuthJsUser = credentials.register
