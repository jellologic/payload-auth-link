import Credentials from '@auth/core/providers/credentials'
import { createAuthJsCredentials, createAuthJsEngine } from '@payload-auth-link/provider-authjs'
import { getPayload, type Payload } from 'payload'
import { exampleBaseURL } from './auth-base-url'

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
