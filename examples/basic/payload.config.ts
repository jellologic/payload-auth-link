import { authLink } from '@payload-auth-link/plugin'
import path from 'path'
import { fileURLToPath } from 'url'
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig } from 'payload'
import { betterAuthCollections, betterAuthProvider } from './lib/auth'
import { authJsCollections, authJsProvider } from './lib/authjs'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)
const baseUrl = process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3100'

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
      url: `file:${path.resolve(dirname, 'payload.db')}`,
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
      fields: [],
    },
    {
      slug: 'pages',
      fields: [{ name: 'title', type: 'text', required: true }],
    },
    ...betterAuthCollections,
    ...authJsCollections,
  ],
  plugins: [
    authLink({
      baseUrl,
      roles: ['admin', 'user'],
      defaultRole: 'user',
      // API keys (Better Auth @better-auth/api-key) present as a
      // distinct session channel; cookie remains the default.
      admitChannels: ['cookie', 'api-key'],
      // Both providers live side by side: Better Auth at /api/auth,
      // Auth.js at /api/authjs. The session service asks each in turn.
      providers: [betterAuthProvider, authJsProvider],
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
