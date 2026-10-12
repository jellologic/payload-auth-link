import { okAsync } from 'neverthrow'
import {
  defineProviderId,
  parseEmail,
  type IdentityProviderPort,
  type ProviderSession,
} from '@payload-auth-link/core'

export const stubCookieName = 'al_stub_session'

type StubSessionRow = {
  readonly providerUserId: string
  readonly email: string
  readonly emailVerified: boolean
  readonly expiresAt: Date
}

/**
 * In-memory identity provider for tests. Sessions live in a `Map` keyed by
 * the `al_stub_session` cookie value.
 */
export function createStubProvider() {
  const sessions = new Map<string, StubSessionRow>()

  const provider: IdentityProviderPort = {
    id: defineProviderId('stub'),
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
    })
    return `${stubCookieName}=${input.sessionId}`
  }

  return { provider, issue, sessions }
}
