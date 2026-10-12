import { authLink } from '@payload-auth-link/plugin'
import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { postgresAdapter } from '@payloadcms/db-postgres'
import { sqliteAdapter } from '@payloadcms/db-sqlite'
import path from 'path'
import { fileURLToPath } from 'url'
import { buildConfig } from 'payload'
import { betterAuthCollections, betterAuthProvider } from './lib/auth'
import { authJsCollections, authJsProvider } from './lib/authjs'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

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
    client: { url: `file:${path.resolve(dirname, 'payload.db')}` },
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
      baseUrl: process.env.EXAMPLE_BASE_URL ?? 'http://localhost:3200',
      secret: process.env.PAYLOAD_SECRET ?? 'local-dev-only-secret-32-chars-min!',
      roles: ['admin', 'user'],
      defaultRole: 'user',
      providers: [betterAuthProvider, authJsProvider],
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
