/**
 * The migrating app's TARGET config for the CLI lifecycle suite
 * (issue #88): the payload-auth fixture's host users (with the
 * `role` select the plugin adopts), the engine's own `ba-*`
 * collections, and the authLink plugin. Loaded by the CLI exactly as a
 * user's `--config` would be — a module whose default export is the
 * built config — so the in-process tests exercise the real boot and
 * teardown path. The connection string comes from
 * `PAL_MIGRATE_TARGET_URL`, set by the suite before the first command.
 */
import { apiKey as apiKeyPlugin } from '@better-auth/api-key'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { admin, anonymous, jwt, magicLink, organization } from 'better-auth/plugins'
import { authLink } from '@payload-auth-link/plugin'
import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'
import { buildConfig, type CollectionConfig } from 'payload'

const ORIGIN = 'http://localhost:3100'
const SECRET = 'cli-lifecycle-secret-cli-lifecycle!'

const hostUsers: CollectionConfig = {
  slug: 'users',
  auth: true,
  fields: [
    { name: 'email', type: 'email', required: true, index: true },
    { name: 'emailVerified', type: 'checkbox', defaultValue: false },
    { name: 'name', type: 'text' },
    { name: 'image', type: 'text' },
    { name: 'department', type: 'text' },
    {
      name: 'role',
      type: 'select',
      hasMany: true,
      options: ['user', 'admin', 'staff', 'frontPlugin'],
      defaultValue: ['user'],
      required: true,
    },
  ],
}

export function targetConfig(options: {
  readonly withAdminPlugins: boolean
  /** The env var naming the database (default `PAL_MIGRATE_TARGET_URL`). */
  readonly urlEnv?: string
}) {
  const urlEnv = options.urlEnv ?? 'PAL_MIGRATE_TARGET_URL'
  const connectionString = process.env[urlEnv]
  if (connectionString === undefined || connectionString === '') {
    throw new Error(`${urlEnv} is not set`)
  }
  const engine = createBetterAuthEngine({
    // The CLI only writes through the Local API; Better Auth itself
    // never needs the instance during these commands.
    getPayload: () => Promise.reject(new Error('not used by the migration CLI')),
    autoDeclare: true,
    options: {
      baseURL: ORIGIN,
      secret: SECRET,
      emailAndPassword: { enabled: true, requireEmailVerification: false },
      advanced: { cookiePrefix: 'bl' },
      plugins: [
        magicLink({ sendMagicLink: async () => {} }),
        organization({ sendInvitationEmail: async () => {} }),
        apiKeyPlugin({ enableMetadata: true }),
        jwt(),
        ...(options.withAdminPlugins ? [admin(), anonymous()] : []),
      ],
      rateLimit: { enabled: false },
    },
  })
  return buildConfig({
    secret: SECRET,
    serverURL: ORIGIN,
    telemetry: false,
    logger: { options: { level: 'silent' } },
    admin: { user: 'users' },
    db: postgresAdapter({ push: false, pool: { connectionString } }),
    collections: [hostUsers, ...engine.collections],
    plugins: [
      authLink({
        baseUrl: ORIGIN,
        roles: ['user', 'admin', 'staff', 'front-plugin'],
        defaultRole: 'user',
        rolesField: 'role',
        roleManagerRoles: ['admin'],
        roleValues: { 'front-plugin': 'frontPlugin' },
        providers: [engine.provider],
        emailVerifiedField: 'emailVerified',
      }),
    ],
  })
}
