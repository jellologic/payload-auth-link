import { randomUUID } from 'node:crypto'
import Credentials from '@auth/core/providers/credentials'
import type { Provider } from '@auth/core/providers'
import { createGoogleOneTapAuthorize } from '@payload-auth-link/provider-authjs'
import type { BetterAuthCustomField } from '@payload-auth-link/provider-better-auth'
import { genericOAuth, multiSession, oneTap, phoneNumber } from 'better-auth/plugins'
import type { CollectionConfig, CollectionSlug, Payload } from 'payload'

/**
 * LOCAL E2E VARIANT ONLY (`E2E_MOCK_IDP=<origin>`, see
 * e2e/playwright.tanstack-idp.config.ts; mirrors the Next example's
 * lib/e2e-idp.ts): the external-identity flows wired
 * against the local mock OIDC provider (`e2e/mock-idp.ts`) instead of
 * hosted services. Unset — every default, dev, and production run —
 * nothing here is wired and the example behaves exactly as before.
 *
 * The variant runs on its own SQLite file (`payload-idp.db`) because it
 * also changes stored data shapes (`roleValues`, the host `department`
 * field, the `memos` collection), and it registers Auth.js as the
 * enterprise-SSO provider (`organizations.ssoProviders: ['authjs']`):
 * every Auth.js session links only on an organization-verified email
 * domain, which would break the default suite's Auth.js specs.
 */
export const mockIdpOrigin: string | null =
  process.env.E2E_MOCK_IDP !== undefined && process.env.E2E_MOCK_IDP !== ''
    ? process.env.E2E_MOCK_IDP
    : null

/** Google OAuth client id the One Tap token audience must match. */
export const oneTapClientId = 'e2e-google-one-tap-client'

/** Canonical role the variant stores under a different value (#56). */
export const mappedRoleValues = { editor: 'contentEditor' } as const

/**
 * The `phoneNumber` plugin's user fields, hand-declared for the Payload
 * adapter (this example declares its plugin schema explicitly rather
 * than through `autoDeclare`). Empty when the variant is off.
 */
export const idpBetterAuthUserFields = (
  mockIdpOrigin === null
    ? []
    : [
        { name: 'phoneNumber', type: 'text', unique: true },
        { name: 'phoneNumberVerified', type: 'boolean' },
      ]
) satisfies readonly BetterAuthCustomField[]

// ---------------------------------------------------------------------------
// Dev SMS outbox: phone OTP codes captured in-process (no SMS gateway)
// ---------------------------------------------------------------------------

export type DevSmsEntry = {
  readonly phoneNumber: string
  readonly code: string
  readonly at: number
}

type OutboxGlobal = typeof globalThis & { __devSmsOutbox?: DevSmsEntry[] }

function outbox(): DevSmsEntry[] {
  // `globalThis`: dev-server module reloading must not fork the outbox
  // between the engine module and the route module (as the mailbox).
  const holder = globalThis as OutboxGlobal
  holder.__devSmsOutbox ??= []
  return holder.__devSmsOutbox
}

/** Codes sent to one number, newest first. */
export function readDevSms(phone: string): DevSmsEntry[] {
  return outbox()
    .filter((entry) => entry.phoneNumber === phone)
    .reverse()
}

// ---------------------------------------------------------------------------
// Better Auth: social OAuth (generic OIDC), One Tap, phone, multi-session
// ---------------------------------------------------------------------------

/** Better Auth plugins of the variant (empty when it is off). */
export function idpBetterAuthPlugins() {
  if (mockIdpOrigin === null) {
    return []
  }
  return [
    // Social OAuth (CAP-3): a standards OIDC provider via discovery.
    genericOAuth({
      config: [
        {
          providerId: 'mock-idp',
          discoveryUrl: `${mockIdpOrigin}/.well-known/openid-configuration`,
          clientId: 'better-auth-e2e',
          clientSecret: 'better-auth-e2e-secret',
          scopes: ['openid', 'email', 'profile'],
          pkce: true,
        },
      ],
    }),
    // One Tap (CAP-4): verifies against Google's own JWKS — Better
    // Auth exposes no JWKS override, so only refusals are observable.
    oneTap({ clientId: oneTapClientId }),
    // Phone sign-in (CAP-9): codes land in the dev SMS outbox.
    phoneNumber({
      sendOTP: ({ phoneNumber: phone, code }) => {
        outbox().push({ phoneNumber: phone, code, at: Date.now() })
        return Promise.resolve()
      },
    }),
    // Several accounts in one browser (CAP-13b).
    multiSession(),
  ]
}

// ---------------------------------------------------------------------------
// Auth.js: enterprise SSO over OIDC, and the One Tap recipe
// ---------------------------------------------------------------------------

/** Auth.js provider id of the mock SSO connection. */
export const mockSsoProviderId = 'mock-sso'

/** Auth.js providers of the variant (empty when it is off). */
export function idpAuthJsProviders(getPayload: () => Promise<Payload>): Provider[] {
  if (mockIdpOrigin === null) {
    return []
  }
  // `defaultAuthJsSlugs.user` as a literal, so the Local API calls
  // type-check against the generated slug union (`payload generate:types`).
  const ajUsers = 'aj-users' satisfies CollectionSlug
  return [
    {
      id: mockSsoProviderId,
      name: 'Mock SSO',
      type: 'oidc',
      issuer: mockIdpOrigin,
      clientId: 'authjs-e2e',
      clientSecret: 'authjs-e2e-secret',
      authorization: { params: { scope: 'openid email profile' } },
    },
    // One Tap recipe (CAP-4) pointed at the mock's Google-shaped JWKS.
    Credentials({
      id: 'google-one-tap',
      name: 'Google One Tap',
      credentials: { credential: { label: 'Google ID token', type: 'text' } },
      authorize: createGoogleOneTapAuthorize({
        clientId: oneTapClientId,
        jwksUrl: `${mockIdpOrigin}/google/certs`,
        upsertUser: async (profile) => {
          const payload = await getPayload()
          const found = await payload.find({
            collection: ajUsers,
            where: { email: { equals: profile.email } },
            limit: 1,
            overrideAccess: true,
          })
          const existing = found.docs[0] as
            { auId?: unknown; email?: unknown; emailVerified?: unknown } | undefined
          if (existing !== undefined) {
            return typeof existing.auId === 'string'
              ? {
                  id: existing.auId,
                  email: profile.email,
                  emailVerified:
                    typeof existing.emailVerified === 'string'
                      ? new Date(existing.emailVerified)
                      : null,
                }
              : null
          }
          // Only ever called for a signature-verified, email-verified
          // Google profile: the stamp records exactly that.
          const verifiedAt = new Date()
          const auId = randomUUID()
          await payload.create({
            collection: ajUsers,
            data: {
              auId,
              email: profile.email,
              ...(profile.name === null ? {} : { name: profile.name }),
              emailVerified: verifiedAt.toISOString(),
            },
            overrideAccess: true,
          })
          return { id: auId, email: profile.email, emailVerified: verifiedAt }
        },
      }),
    }),
  ]
}

// ---------------------------------------------------------------------------
// Payload: host field + collection whose access reads it (#56/#57)
// ---------------------------------------------------------------------------

/** One field of `req.user`; host fields are not on the session type. */
function userField(user: unknown, key: string): unknown {
  return typeof user === 'object' && user !== null
    ? (user as Record<string, unknown>)[key]
    : undefined
}

function hasRole(user: unknown, role: string): boolean {
  const roles = userField(user, 'roles')
  return Array.isArray(roles) && roles.includes(role)
}

/**
 * `memos`: reads need the host `department` field (only present on
 * `req.user` with `reqUser: 'document'`), creates need the canonical
 * `editor` role (stored as `contentEditor`).
 */
export const memosCollection: CollectionConfig = {
  slug: 'memos',
  fields: [{ name: 'title', type: 'text', required: true }],
  access: {
    read: ({ req }) => userField(req.user, 'department') === 'research',
    create: ({ req }) => hasRole(req.user, 'editor') || hasRole(req.user, 'admin'),
    update: ({ req }) => hasRole(req.user, 'admin'),
    delete: ({ req }) => hasRole(req.user, 'admin'),
  },
}
