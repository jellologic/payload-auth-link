import { authLink } from '@payload-auth-link/plugin'
import path from 'path'
import { fileURLToPath } from 'url'
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig } from 'payload'
import { betterAuthCollections, betterAuthProvider } from './lib/auth'
import { legacySessionWindow } from './lib/auth-cookie-names'
import { authJsCollections, authJsProvider } from './lib/authjs'
import { mappedRoleValues, memosCollection, mockIdpOrigin } from './lib/e2e-idp'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)
const baseUrl = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100'

// MFA-policy variant (`E2E_MFA_POLICY=1`, e2e/playwright.mfa.config.ts):
// `policies.requireMfaForRoles` throws at wiring unless EVERY provider
// declares the `mfa` capability, and Auth.js cannot (decision D4). The
// variant therefore registers Better Auth alone and gates a dedicated
// `auditor` role — never `admin`: the seeded admin signs in with local
// Payload credentials (no MFA proof), so gating `admin` would withhold
// the very role that grants roles. It runs on its own SQLite file so
// the extra role never reaches the default example database.
const mfaPolicy = process.env.E2E_MFA_POLICY === '1'

// External-IdP variant (`E2E_MOCK_IDP=<mock origin>`,
// e2e/playwright.idp.config.ts; see lib/e2e-idp.ts): social OAuth, One
// Tap, phone, and multi-session against a local mock IdP, plus the
// options that change stored data — `roleValues` (`editor` stored as
// `contentEditor`), `reqUser: 'document'` with a host `department`
// field read by the `memos` collection's access, and Auth.js as the
// enterprise-SSO provider (`organizations.ssoProviders`). Own SQLite
// file, so none of it reaches the default example database.
const idpVariant = mockIdpOrigin !== null

function sqliteFile(): string {
  if (mfaPolicy) {
    return 'payload-mfa.db'
  }
  return idpVariant ? 'payload-idp.db' : 'payload.db'
}

// Parity runs point PAYLOAD_DB elsewhere; default local dev stays on
// the SQLite file. Postgres uses `push` (no migration files in the
// example) and a per-run database name so every e2e run starts from a
// fresh schema — the adapter creates the database on connect. Mongo
// runs against mongodb-memory-server (per-run replset, fresh by
// construction) via MONGODB_URI from the e2e wrapper.
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
      throw new Error('PAYLOAD_DB=mongo requires MONGODB_URI (run via bun run e2e:mongo)')
    }
    // No transactions: the example runs three Payload instances (Next
    // plugin + both provider loaders) whose concurrent transactions
    // lock-fight on a single-node memory server. Our adapters issue
    // single-document Local API calls and never use multi-doc
    // transactions, so this loses no product coverage.
    return mongooseAdapter({ url, transactionOptions: false })
  }
  return sqliteAdapter({
    client: {
      url: `file:${path.resolve(dirname, sqliteFile())}`,
    },
  })
}

const db = exampleDb()

export default buildConfig({
  secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
  serverURL: baseUrl,
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
      baseUrl,
      roles: mfaPolicy
        ? ['admin', 'user', 'auditor']
        : idpVariant
          ? ['admin', 'user', 'editor']
          : ['admin', 'user'],
      ...(idpVariant ? { roleValues: mappedRoleValues, reqUser: 'document' as const } : {}),
      defaultRole: 'user',
      // #55/#72: /admin/login through the provider (plus the
      // break-glass local form for unlinked operators).
      admin: { loginView: 'provider' },
      // API keys (Better Auth @better-auth/api-key) present as a
      // distinct session channel; cookie remains the default.
      admitChannels: ['cookie', 'api-key'],
      // Both providers live side by side: Better Auth at /api/auth,
      // Auth.js at /api/authjs. The session service asks each in turn.
      // The MFA-policy variant drops Auth.js (see `mfaPolicy` above).
      providers: mfaPolicy ? [betterAuthProvider] : [betterAuthProvider, authJsProvider],
      // CAP-11: Payload-owned organizations + memberships, with the
      // list/create/invite/accept endpoints under
      // /api/auth-link/organizations*.
      // The external-IdP variant makes Auth.js the enterprise-SSO
      // provider (CAP-15): its sessions link only on an email domain an
      // organization has verified.
      organizations: idpVariant ? { enabled: true, ssoProviders: ['authjs'] } : { enabled: true },
      // Asserts the engine's coexistence window (issue #51/#72): wiring
      // throws if the two ever disagree.
      legacySessions: legacySessionWindow,
      // CAP-6: sessions without MFA proof are treated as missing
      // `auditor` (variant only; see `mfaPolicy` above).
      ...(mfaPolicy ? { policies: { requireMfaForRoles: ['auditor'] } } : {}),
    }),
  ],
  onInit: async (payload) => {
    // Dev-only admin seed, explicitly opted in: a known-password admin
    // must never appear on a fresh database by default. The e2e harness
    // sets both variables (see `e2e/dev-admin.ts`); local explorers set
    // them by hand. Provider users are provisioned just-in-time at first
    // session verification instead of seeding — sign up through /sign-in
    // to see it happen.
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
    })
    if (existing.totalDocs === 0) {
      await payload.create({
        collection: 'users',
        data: {
          email: 'dev@payload-auth-link.test',
          password,
          roles: ['admin'],
        },
      })
    }
  },
})
