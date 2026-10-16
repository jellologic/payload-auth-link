import { authLink } from '@payload-auth-link/plugin'
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import path from 'path'
import { fileURLToPath } from 'url'
import { buildConfig } from 'payload'
import { legacySessionWindow } from './lib/auth-base-url'
import { betterAuthCollections, betterAuthProvider } from './lib/auth'
import { authJsCollections, authJsProvider } from './lib/authjs'
import { mappedRoleValues, memosCollection, mockIdpOrigin } from './lib/e2e-idp'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

// External-IdP variant (`E2E_MOCK_IDP=<mock origin>`,
// e2e/playwright.tanstack-idp.config.ts; see lib/e2e-idp.ts): social
// OAuth, One Tap, phone, and multi-session against a local mock IdP,
// plus the options that change stored data — `roleValues` (`editor`
// stored as `contentEditor`), `reqUser: 'document'` with a host
// `department` field read by the `memos` collection's access, and
// Auth.js as the enterprise-SSO provider (`organizations.ssoProviders`).
// Own SQLite file, so none of it reaches the default example database.
const idpVariant = mockIdpOrigin !== null

// Parity runs point PAYLOAD_DB elsewhere (mirrors the Next example);
// default local dev stays on the SQLite file. Postgres uses `push` (no
// migration files in the example) and a per-run database name so every
// e2e run starts from a fresh schema — the adapter creates the database
// on connect. Mongo runs against mongodb-memory-server (per-run replset,
// fresh by construction) via MONGODB_URI from the e2e wrapper.
function exampleDb() {
  if (process.env.PAYLOAD_DB === 'postgres') {
    return postgresAdapter({
      pool: {
        connectionString:
          process.env.DATABASE_URL ?? 'postgres://postgres:payload@localhost:5433/pal_e2e_default',
      },
      push: true,
    })
  }
  if (process.env.PAYLOAD_DB === 'mongo') {
    const url = process.env.MONGODB_URI
    if (!url) {
      throw new Error('PAYLOAD_DB=mongo requires MONGODB_URI (run via bun run e2e:tanstack-mongo)')
    }
    // No transactions: the example runs several Payload instances
    // (plugin + provider loaders) whose concurrent transactions
    // lock-fight on a single-node memory server. Our adapters issue
    // single-document Local API calls and never use multi-doc
    // transactions, so this loses no product coverage.
    return mongooseAdapter({ url, transactionOptions: false })
  }
  return sqliteAdapter({
    client: {
      url: `file:${path.resolve(dirname, idpVariant ? 'payload-idp.db' : 'payload.db')}`,
    },
  })
}

const db = exampleDb()

export default buildConfig({
  secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
  serverURL: process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3200',
  db,
  collections: [
    {
      slug: 'users',
      auth: true,
      // Host field the plugin's session projection never carries.
      fields: idpVariant ? [{ name: 'department', type: 'text' }] : [],
    },
    {
      slug: 'pages',
      fields: [{ name: 'title', type: 'text', required: true }],
    },
    ...(idpVariant ? [memosCollection] : []),
    ...betterAuthCollections,
    ...authJsCollections,
  ],
  plugins: [
    authLink({
      baseUrl: process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3200',
      roles: idpVariant ? ['admin', 'user', 'editor'] : ['admin', 'user'],
      ...(idpVariant ? { roleValues: mappedRoleValues, reqUser: 'document' as const } : {}),
      // API keys present as a distinct session channel.
      admitChannels: ['cookie', 'api-key'],
      defaultRole: 'user',
      // #55/#72: /admin/login through the provider (plus the
      // break-glass local form for unlinked operators) — mirrors the
      // Next example.
      admin: { loginView: 'provider' },
      providers: [betterAuthProvider, authJsProvider],
      // CAP-11: Payload-owned organizations + memberships, with the
      // list/create/invite/accept endpoints under
      // /api/auth-link/organizations* (mirrors the Next example).
      // The external-IdP variant makes Auth.js the enterprise-SSO
      // provider (CAP-15): its sessions link only on an email domain an
      // organization has verified.
      organizations: idpVariant ? { enabled: true, ssoProviders: ['authjs'] } : { enabled: true },
      // Asserts the engine's coexistence window (issue #51/#72): wiring
      // throws if the two ever disagree.
      legacySessions: legacySessionWindow,
    }),
  ],
  onInit: async (payload) => {
    // Dev-only admin seed, explicitly opted in (mirrors the Next
    // example gate, plus v4's required overrideAccess): a known-password
    // admin must never appear on a fresh database by default.
    if (process.env.ALLOW_DEV_ADMIN_SEED !== 'true') {
      return
    }
    const password = process.env.DEV_ADMIN_PASSWORD
    if (!password) {
      throw new Error('ALLOW_DEV_ADMIN_SEED is set but DEV_ADMIN_PASSWORD is missing')
    }
    const existing = await payload.find({
      collection: 'users',
      where: { email: { equals: 'dev@payload-auth-link.test' } },
      limit: 1,
      overrideAccess: true,
    })
    if (existing.totalDocs === 0) {
      await payload.create({
        collection: 'users',
        data: { email: 'dev@payload-auth-link.test', password, roles: ['admin'] },
        overrideAccess: true,
      })
    }
  },
})
