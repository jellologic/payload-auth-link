import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { nextCookies } from 'better-auth/next-js'
import { getPayload, type Payload } from 'payload'
import { exampleBaseURL } from './auth-cookie-names'

const baseURL = exampleBaseURL

let cachedPayload: Promise<Payload> | undefined

/**
 * Payload loader for the Better Auth database adapter (and the local-only
 * dev stamping route). The config import is dynamic (and only runs on
 * first database access, long after config evaluation), which keeps
 * `payload.config.ts` → `lib/auth.ts` acyclic.
 */
export function loadPayload(): Promise<Payload> {
  cachedPayload ??= import('../payload.config').then((mod) => getPayload({ config: mod.default }))
  return cachedPayload
}

export const engine = createBetterAuthEngine({
  getPayload: loadPayload,
  options: {
    baseURL,
    secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
    // Framework cookie plugin, declared by the builder exactly as
    // Better Auth documents: required for cookie handling in Next.js
    // server actions. The engine never touches this list.
    plugins: [nextCookies()],
    emailAndPassword: {
      enabled: true,
      // Local example only: no email delivery here, so verification is
      // off. The engine requires verification by default — production
      // builders keep the default and configure an email sender.
      requireEmailVerification: false,
    },
    // Builder-owned throttle via Better Auth's own limiter (the library
    // ships none itself). Better Auth's default special rules allow 3
    // sign-ups/sign-ins per 10s per IP — too tight for shared-IP
    // dev/e2e (no trusted client IP here, so every request shares one
    // bucket), so the example raises those two paths to a dev-scale
    // ceiling. Production deployments tune down, resolve real client
    // IPs, and back the limiter with shared storage.
    rateLimit: {
      enabled: true,
      window: 60,
      max: 1000,
      customRules: {
        '/sign-up/email': { window: 60, max: 100 },
        '/sign-in/email': { window: 60, max: 100 },
      },
    },
  },
})

export const { auth, provider: betterAuthProvider, collections: betterAuthCollections } = engine
