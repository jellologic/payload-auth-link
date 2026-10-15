import { assertProviderConformance } from '@payload-auth-link/core/testing'
import { describe, it } from 'vitest'
import { createBetterAuthProvider, type BetterAuthServerApi } from '../port.js'

const cookieNames = ['better-auth.session_token']

// PORT-5: the shared conformance kit over the real port narrowing.
// Provider-specific pinning (S3/S4 sources, fail-closed malformed
// claims) stays in port.test.ts; this proves the cross-provider
// contract (claims, actor, channel, capabilities, revoke) once.
describe('better-auth provider conformance (PORT-5 kit)', () => {
  it('conforms', async () => {
    await assertProviderConformance(() => {
      const user = {
        id: 'ba-1',
        email: 'user@example.com',
        emailVerified: true,
        twoFactorEnabled: true,
      }
      const expiresAt = new Date('2026-02-01T00:00:00.000Z')
      const rows = new Map<string, unknown>([
        [
          'tok-verified',
          {
            session: {
              token: 'tok-verified',
              expiresAt,
              activeOrganizationId: 'org-1',
              authenticationMethod: 'two-factor',
            },
            user,
          },
        ],
        [
          'tok-unverified',
          {
            session: {
              token: 'tok-unverified',
              expiresAt,
              activeOrganizationId: 'org-1',
              authenticationMethod: 'two-factor',
            },
            user: { ...user, emailVerified: false },
          },
        ],
        [
          'tok-impersonated',
          {
            session: {
              token: 'tok-impersonated',
              expiresAt,
              activeOrganizationId: 'org-1',
              impersonatedBy: 'ba-admin',
              authenticationMethod: 'two-factor',
            },
            user,
          },
        ],
      ])
      const auth: BetterAuthServerApi = {
        api: {
          getSession: ({ headers }) => {
            const token = /better-auth\.session_token=([^;]+)/.exec(
              headers.get('cookie') ?? ''
            )?.[1]
            return Promise.resolve(token === undefined ? null : (rows.get(token) ?? null))
          },
        },
        $context: Promise.resolve({
          internalAdapter: {
            deleteSession: (token) => {
              rows.delete(token)
              return Promise.resolve()
            },
            findSessions: (tokens: string[]) =>
              Promise.resolve(
                tokens.filter((token) => rows.has(token)).map((token) => rows.get(token))
              ),
            deleteUserSessions: (userId) => {
              for (const [token, row] of rows) {
                if (
                  typeof row === 'object' &&
                  row !== null &&
                  'user' in row &&
                  typeof row.user === 'object' &&
                  row.user !== null &&
                  'id' in row.user &&
                  row.user.id === userId
                ) {
                  rows.delete(token)
                }
              }
              return Promise.resolve()
            },
          },
        }),
      }
      // The fixture rows simulate the admin plugin's
      // `impersonatedBy`, so the port declares the capability.
      const port = createBetterAuthProvider({
        auth,
        sessionCookieNames: cookieNames,
        impersonation: true,
      })
      const expected = {
        providerUserId: 'ba-1',
        email: 'user@example.com',
        emailVerified: true,
        channel: 'cookie' as const,
        // Assurance reads the recorded per-session method.
        methods: ['two-factor'] as const,
        mfa: true,
        organizationId: 'org-1',
      }
      const headersFor = (token: string) =>
        new Headers({ cookie: `better-auth.session_token=${token}` })
      return {
        port,
        scenarios: {
          session: { headers: headersFor('tok-verified'), expected },
          unverifiedSession: {
            headers: headersFor('tok-unverified'),
            expected: { ...expected, emailVerified: false },
          },
          impersonatedSession: {
            headers: headersFor('tok-impersonated'),
            expectedActorProviderUserId: 'ba-admin',
          },
          noSession: { headers: new Headers() },
        },
      }
    })
  })
})
