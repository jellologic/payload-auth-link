import { assertProviderConformance } from '@payload-auth-link/core/testing'
import { describe, it } from 'vitest'
import { createAuthJsProvider, type AuthJsSessionApi } from '../port.js'

const cookieNames = ['authjs.session-token', 'authjs.session-token.0', 'authjs.session-token.1']

// PORT-5: the shared conformance kit over the real port narrowing.
// Provider-specific pinning (chunked cookies, fail-closed payloads)
// stays in port.test.ts; this proves the cross-provider contract
// (claims, channel, capabilities, revoke) once.
describe('authjs provider conformance (PORT-5 kit)', () => {
  it('conforms', async () => {
    await assertProviderConformance(() => {
      const bodies = new Map<string, unknown>([
        [
          'tok-verified',
          {
            user: { id: 'au-1', email: 'a@b.co', emailVerified: true },
            expires: '2026-06-01T00:00:00.000Z',
          },
        ],
        [
          'tok-unverified',
          {
            user: { id: 'au-1', email: 'a@b.co', emailVerified: false },
            expires: '2026-06-01T00:00:00.000Z',
          },
        ],
      ])
      const sessions: AuthJsSessionApi = {
        readSession: (headers) => {
          const token = /authjs\.session-token=([^;]+)/.exec(headers.get('cookie') ?? '')?.[1]
          return Promise.resolve(token === undefined ? null : (bodies.get(token) ?? null))
        },
        revokeSession: (sessionId) => {
          bodies.delete(sessionId)
          return Promise.resolve(undefined)
        },
      }
      const port = createAuthJsProvider({ sessions, sessionCookieNames: cookieNames })
      const expected = {
        providerUserId: 'au-1',
        email: 'a@b.co',
        emailVerified: true,
        channel: 'cookie' as const,
        methods: 'unknown' as const,
        mfa: 'unknown' as const,
        organizationId: null,
      }
      const headersFor = (token: string) => new Headers({ cookie: `authjs.session-token=${token}` })
      return {
        port,
        scenarios: {
          session: { headers: headersFor('tok-verified'), expected },
          unverifiedSession: {
            headers: headersFor('tok-unverified'),
            expected: { ...expected, emailVerified: false },
          },
          noSession: { headers: new Headers() },
        },
      }
    })
  })
})
