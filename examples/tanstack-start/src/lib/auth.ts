import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { apiKey } from '@better-auth/api-key'
import { passkey } from '@better-auth/passkey'
import { admin, anonymous, emailOTP, magicLink, twoFactor } from 'better-auth/plugins'
import { tanstackStartCookies } from 'better-auth/tanstack-start'
import { getPayload, type Payload } from 'payload'
import { exampleBaseURL, legacySessionWindow } from './auth-base-url'
import { recordDevMail } from './dev-mailbox.js'

const baseURL = exampleBaseURL

let cachedPayload: Promise<Payload> | undefined

/**
 * Payload loader for the Better Auth database adapter (and the local-only
 * dev stamping route). The config import is dynamic (and only runs on
 * first database access, long after config evaluation), which keeps
 * `payload.config.ts` → `lib/auth.ts` acyclic.
 */
export function loadPayload(): Promise<Payload> {
  cachedPayload ??= import('@payload-config').then((mod) => getPayload({ config: mod.default }))
  return cachedPayload
}

export const engine = createBetterAuthEngine({
  getPayload: loadPayload,
  customFields: {
    user: [
      { name: 'isAnonymous', type: 'boolean' },
      { name: 'twoFactorEnabled', type: 'boolean' },
      // Better Auth `admin()` (impersonation, CAP-8): the provider-side
      // operator role and ban state. Provider-native — Payload roles
      // stay the authority for Payload access.
      { name: 'role', type: 'text' },
      { name: 'banned', type: 'boolean' },
      { name: 'banReason', type: 'text' },
      { name: 'banExpires', type: 'date' },
    ],
    // `admin()` marks impersonated sessions with the operator's id.
    session: [{ name: 'impersonatedBy', type: 'text' }],
  },
  // Coexistence with legacy payload-auth session cookies (issue #51).
  legacySessions: legacySessionWindow,
  // Plugin-owned models (CAP-5/6); see the Next example's notes.
  customModels: [
    {
      model: 'twoFactor',
      fields: [
        { name: 'secret', type: 'text', required: true },
        { name: 'backupCodes', type: 'text', required: true },
        { name: 'userId', type: 'text', required: true },
        { name: 'verified', type: 'boolean' },
        { name: 'failedVerificationCount', type: 'number' },
        { name: 'lockedUntil', type: 'date' },
      ],
    },
    {
      // API keys (@better-auth/api-key): declared like any satellite
      // model — see the capabilities guide's API keys recipe.
      model: 'apikey',
      fields: [
        // createdAt/updatedAt are Payload-owned and excluded, like
        // every custom model.
        { name: 'configId', type: 'text', required: true },
        { name: 'enabled', type: 'boolean' },
        { name: 'expiresAt', type: 'date' },
        { name: 'key', type: 'text', required: true },
        { name: 'lastRefillAt', type: 'date' },
        { name: 'lastRequest', type: 'date' },
        { name: 'metadata', type: 'text' },
        { name: 'name', type: 'text' },
        { name: 'permissions', type: 'text' },
        { name: 'prefix', type: 'text' },
        { name: 'rateLimitEnabled', type: 'boolean' },
        { name: 'rateLimitMax', type: 'number' },
        { name: 'rateLimitTimeWindow', type: 'number' },
        { name: 'referenceId', type: 'text', required: true },
        { name: 'refillAmount', type: 'number' },
        { name: 'refillInterval', type: 'number' },
        { name: 'remaining', type: 'number' },
        { name: 'requestCount', type: 'number' },
        { name: 'start', type: 'text' },
      ],
    },
    {
      model: 'passkey',
      fields: [
        { name: 'name', type: 'text' },
        { name: 'publicKey', type: 'text', required: true },
        { name: 'userId', type: 'text', required: true },
        { name: 'credentialID', type: 'text', required: true },
        { name: 'counter', type: 'number', required: true },
        { name: 'deviceType', type: 'text', required: true },
        { name: 'backedUp', type: 'boolean', required: true },
        { name: 'transports', type: 'text' },
        { name: 'aaguid', type: 'text' },
      ],
    },
  ],
  options: {
    baseURL,
    secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
    // Framework cookie plugin, declared by the builder exactly as
    // Better Auth documents: TanStack Start owns cookie I/O here (not
    // Next.js), so this is `tanstackStartCookies()`, never
    // `nextCookies()`. The engine never touches this list.
    // Passwordless + guest plugins (CAP-1/2/10): all "mail" lands in
    // the local dev mailbox — production builders pass real senders.
    // Cookie integration stays LAST so plugin cookies forward.
    plugins: [
      magicLink({
        sendMagicLink: ({ email, url }) => {
          recordDevMail({ kind: 'magic-link', email, url })
          return Promise.resolve()
        },
      }),
      emailOTP({
        sendVerificationOTP: ({ email, otp }) => {
          recordDevMail({ kind: 'email-otp', email, code: otp })
          return Promise.resolve()
        },
      }),
      anonymous(),
      twoFactor(),
      apiKey({ defaultPrefix: 'bock_', enableMetadata: true, enableSessionForAPIKeys: true }),
      passkey({
        rpID: new URL(baseURL).hostname,
        rpName: 'payload-auth-link example',
        origin: baseURL,
      }),
      // Impersonation (CAP-8): Better Auth operators (BA `role:
      // 'admin'`) can impersonate users. The plugin sees the actor and
      // denies the admin panel, role writes, and organization writes
      // while impersonating.
      admin(),
      tanstackStartCookies(),
    ],
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
        // Attempt caps on the passwordless routes (CAP-18).
        '/sign-in/magic-link': { window: 60, max: 30 },
        '/email-otp/send-verification-otp': { window: 60, max: 30 },
        '/sign-in/email-otp': { window: 60, max: 60 },
      },
    },
  },
})

export const { auth, provider: betterAuthProvider, collections: betterAuthCollections } = engine
