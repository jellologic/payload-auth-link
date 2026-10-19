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
export function createStubProvider(options?: {
  readonly capabilities?: readonly Capability[]
  /** Registry id override, so tests can wire two stubs side by side. */
  readonly id?: string
  /** Coexistence window to expose on the port (#72 cross-check tests). */
  readonly legacySessions?: { readonly until: string; readonly cookieNames: readonly string[] }
  /** Omit `sessionCookie` (simulates a non-cookie-transport provider). */
  readonly omitSessionCookie?: boolean
}) {
  const sessions = new Map<string, StubSessionRow>()
  // Server-minted sessions (issue #54): the provider's mint API
  // writes here AND plants a verifyable stub session row.
  const minted = new Map<
    string,
    { sessionId: string; token: string; providerUserId: string; expiresAt: Date }
  >()
  let mintCounter = 0

  const provider: IdentityProviderPort = {
    id: defineProviderId(options?.id ?? 'stub'),
    capabilities: new Set<Capability>([
      ...(options?.capabilities ?? []),
      'revoke-user-sessions',
      'server-session-create',
      'server-session-list',
    ]),
    sessionCookieNames: [stubCookieName],
    ...(options?.legacySessions === undefined
      ? {}
      : {
          legacySessions: {
            ...options.legacySessions,
            cookieNames: [...options.legacySessions.cookieNames],
          },
        }),
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
      minted.delete(sessionId)
      return okAsync(undefined)
    },
    createProviderSession: (providerUserId, options) => {
      mintCounter += 1
      const sessionId = `minted-${mintCounter}`
      const token = `minted-token-${mintCounter}`
      minted.set(sessionId, { sessionId, token, providerUserId, expiresAt: options.expiresAt })
      const mintedEmail = parseEmail('minted@test.dev')
      if (mintedEmail.isErr()) {
        throw mintedEmail.error
      }
      sessions.set(token, {
        providerUserId,
        email: mintedEmail.value,
        emailVerified: true,
        expiresAt: options.expiresAt,
      })
      return okAsync({ sessionId, token, storedExpiresAt: options.expiresAt })
    },
    revokeUserSessions: (providerUserId) => {
      for (const [id, row] of minted) {
        if (row.providerUserId === providerUserId) {
          minted.delete(id)
          sessions.delete(row.token)
        }
      }
      return okAsync(undefined)
    },
    listProviderSessions: (providerUserId) =>
      okAsync(
        [...minted.values()]
          .filter((row) => row.providerUserId === providerUserId)
          .map((row) => ({ sessionId: row.sessionId, expiresAt: row.expiresAt }))
      ),
    ...(options?.omitSessionCookie === true
      ? {}
      : {
          // The signed VALUE (`token.<sig>`), per the port contract —
          // injectable into a request `Cookie` header (#125).
          sessionCookie: (token: string) => Promise.resolve(`${token}.stub-signature`),
          // The full `Set-Cookie` line, what `createSession().setCookie`
          // returns.
          sessionCookieLine: (token: string) =>
            Promise.resolve(`al_stub_session=${token}; Path=/; HttpOnly; SameSite=Lax`),
        }),
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
