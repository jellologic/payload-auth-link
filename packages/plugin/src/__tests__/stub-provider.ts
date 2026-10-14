import { okAsync } from 'neverthrow'
import {
  defineProviderId,
  parseEmail,
  type Capability,
  type IdentityProviderPort,
  type ProviderSession,
  type SessionChannel,
} from '@payload-auth-link/core'

export const stubCookieName = 'al_stub_session'

type StubSessionRow = {
  readonly providerUserId: string
  readonly email: string
  readonly emailVerified: boolean
  readonly expiresAt: Date
  /** Presentation channel reported for this session (CAP-13a). */
  readonly channel?: SessionChannel | undefined
  /** Impersonating operator's provider user id, when any (CAP-8b). */
  readonly actorProviderUserId?: string | undefined
  /** Anonymous guest session (CAP-10). */
  readonly anonymous?: boolean | undefined
  /** Session carries a satisfied MFA proof (CAP-6). */
  readonly mfaSatisfied?: boolean | undefined
  /** Active organization reported on the session (organization plugin). */
  readonly organizationId?: string | undefined
}

/**
 * In-memory identity provider for tests. Sessions live in a `Map` keyed by
 * the `al_stub_session` cookie value.
 */
export function createStubProvider(options?: { readonly capabilities?: readonly Capability[] }) {
  const sessions = new Map<string, StubSessionRow>()

  const provider: IdentityProviderPort = {
    id: defineProviderId('stub'),
    capabilities: new Set<Capability>(options?.capabilities ?? []),
    sessionCookieNames: [stubCookieName],
    getSession: (headers) => {
      const cookie = headers.get('cookie') ?? ''
      const match = new RegExp(`${stubCookieName}=([^;]+)`).exec(cookie)
      const sessionId = match?.[1]
      const found = sessionId === undefined ? undefined : sessions.get(sessionId)
      if (!found || sessionId === undefined) {
        return okAsync(null)
      }
      const email = parseEmail(found.email)
      if (email.isErr()) {
        return okAsync(null)
      }
      const session: ProviderSession = {
        sessionId,
        providerUserId: found.providerUserId,
        email: email.value,
        emailVerified: found.emailVerified,
        expiresAt: found.expiresAt,
        identity: {
          email: { value: email.value, verified: found.emailVerified },
          phone: null,
          anonymous: found.anonymous ?? false,
        },
        assurance:
          found.mfaSatisfied === true
            ? { methods: ['password'], mfa: true }
            : { methods: 'unknown', mfa: 'unknown' },
        actor:
          found.actorProviderUserId === undefined
            ? null
            : { providerUserId: found.actorProviderUserId },
        organizationId: found.organizationId ?? null,
        channel: found.channel ?? 'cookie',
      }
      return okAsync(session)
    },
    revokeSession: (sessionId) => {
      sessions.delete(sessionId)
      return okAsync(undefined)
    },
  }

  const issue = (
    input: { sessionId: string } & Omit<StubSessionRow, 'emailVerified'> & {
        emailVerified?: boolean | undefined
      }
  ): string => {
    sessions.set(input.sessionId, {
      providerUserId: input.providerUserId,
      email: input.email,
      emailVerified: input.emailVerified ?? true,
      expiresAt: input.expiresAt,
      channel: input.channel,
      actorProviderUserId: input.actorProviderUserId,
      anonymous: input.anonymous,
      mfaSatisfied: input.mfaSatisfied,
      organizationId: input.organizationId,
    })
    return `${stubCookieName}=${input.sessionId}`
  }

  return { provider, issue, sessions }
}
