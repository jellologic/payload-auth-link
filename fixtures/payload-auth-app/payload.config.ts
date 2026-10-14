/**
 * The fixture app's payload-auth 1.9.4 config — the layout a
 * production payload-auth app has, mirrored feature for feature
 * (issue #59). Everything the migration kit is tested against is
 * produced by RUNNING this config, never hand-written rows.
 *
 * Deliberate fixture choices, each traced to the journey issue #60:
 * - `roles: ['user', 'admin', 'staff', 'frontPlugin']` — the app's
 *   non-canonical camelCase role must survive untouched (#56).
 * - `users.collectionOverrides` adds `department`, and
 *   `pluginCollectionOverrides.organizations` adds a group, an array
 *   and a relationship — host-added fields Better Auth cannot see and
 *   must never clobber (#49).
 * - `advanced.cookiePrefix: 'bl'` — the legacy session cookie names
 *   coexistence must honor (#51).
 * - plugins: magicLink (verification rows), organization
 *   (orgs/members/invitations), apiKey (keys with metadata), jwt
 *   (jwks), nextCookies (as a real app runs).
 */
import { apiKey } from '@better-auth/api-key'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { nextCookies } from 'better-auth/next-js'
import { jwt, magicLink, organization } from 'better-auth/plugins'
import { buildConfig } from 'payload'
import { betterAuthPlugin } from 'payload-auth'

export default buildConfig({
  secret: 'fixture-secret-fixture-secret-fixture',
  telemetry: false,
  db: postgresAdapter({
    push: true,
    pool: {
      connectionString:
        process.env.DATABASE_URL ?? 'postgres://postgres:payload@localhost:5433/pal_fixture',
    },
  }),
  collections: [],
  plugins: [
    betterAuthPlugin({
      users: {
        roles: ['user', 'admin', 'staff', 'frontPlugin'],
        defaultRole: 'user',
        defaultAdminRole: 'admin',
        // Host-added field: invisible to Better Auth, written only by
        // the app.
        collectionOverrides: ({ collection }) => ({
          ...collection,
          fields: [...collection.fields, { name: 'department', type: 'text' }],
        }),
      },
      pluginCollectionOverrides: {
        organizations: ({ collection }) => ({
          ...collection,
          fields: [
            ...collection.fields,
            {
              name: 'billing',
              type: 'group',
              fields: [
                { name: 'plan', type: 'text', defaultValue: 'free' },
                { name: 'seats', type: 'number', defaultValue: 5 },
              ],
            },
            { name: 'tags', type: 'array', fields: [{ name: 'label', type: 'text' }] },
            { name: 'owner', type: 'relationship', relationTo: 'users' },
          ],
        }),
      },
      betterAuthOptions: {
        baseURL: 'http://localhost:3100',
        advanced: { cookiePrefix: 'bl' },
        emailAndPassword: { enabled: true, requireEmailVerification: false },
        socialProviders: {
          google: { clientId: 'fixture-client', clientSecret: 'fixture-secret' },
        },
        plugins: [
          magicLink({ sendMagicLink: async () => {} }),
          organization({
            sendInvitationEmail: async () => {},
          }),
          apiKey({ enableMetadata: true }),
          jwt(),
          nextCookies(),
        ],
      },
    }),
  ],
})
