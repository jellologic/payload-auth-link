import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { apiKey } from '@better-auth/api-key'
import { passkey } from '@better-auth/passkey'
import { nextCookies } from 'better-auth/next-js'
import { admin, anonymous, emailOTP, magicLink, twoFactor } from 'better-auth/plugins'
import { getPayload, type Payload } from 'payload'
import { exampleBaseURL, legacySessionWindow } from './auth-cookie-names'
import { recordDevMail } from './dev-mailbox'

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
  // Plugin-owned user fields the adapter must serve (CAP-10's
  // anonymous marker, CAP-8's admin plugin). Declared here, generated
  // into ba-users / ba-sessions.
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
  // Derived declarations (issue #17): the plugin models (twoFactor,
  // passkey, ...) and their fields come from Better Auth's own
  // getAuthTables output, so a BA schema bump cannot drift from the
  // declarations. Pin the derived output in a snapshot test to keep
  // a drift alarm (see the capabilities guide).
  autoDeclare: true,
  options: {
    baseURL,
    secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
    // Framework cookie plugin, declared by the builder exactly as
    // Better Auth documents: required for cookie handling in Next.js
    // server actions. The engine never touches this list.
    // Passwordless + guest plugins (CAP-1/2/10): all "mail" lands in
    // the local dev mailbox — production builders pass real senders.
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
      passkey({
        rpID: new URL(baseURL).hostname,
        rpName: 'payload-auth-link example',
        origin: baseURL,
      }),
      apiKey({ defaultPrefix: 'bock_', enableMetadata: true, enableSessionForAPIKeys: true }),
      // Impersonation (CAP-8): Better Auth operators (BA `role:
      // 'admin'`) can impersonate users. The plugin sees the actor and
      // denies the admin panel, role writes, and organization writes
      // while impersonating.
      admin(),
      // Cookie integration goes LAST so plugin-set cookies forward.
      nextCookies(),
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
        // Verify/send routes are attempt-capped per IP (CAP-18): OTP
        // guesses and link requests are the brute-force surface.
        // Generous here (shared-IP dev); production tunes these down
        // hard and adds per-identifier counters (see the guide).
        '/sign-in/magic-link': { window: 60, max: 30 },
        '/email-otp/send-verification-otp': { window: 60, max: 30 },
        '/sign-in/email-otp': { window: 60, max: 60 },
      },
    },
  },
})

export const { auth, provider: betterAuthProvider, collections: betterAuthCollections } = engine
