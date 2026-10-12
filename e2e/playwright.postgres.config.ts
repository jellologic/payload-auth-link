import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'

// Postgres parity run: same specs, same example, `PAYLOAD_DB=postgres`.
// A per-run database name keeps every run on a fresh schema (the
// adapter creates it on connect); CI points PGHOST at its service.
const runId = process.env.GITHUB_RUN_ID ?? `${Date.now()}`
const dbName = `pal_e2e_${runId}`.replace(/[^a-z0-9_]/gi, '_').toLowerCase()
const databaseUrl =
  process.env.DATABASE_URL ??
  `postgres://${process.env.PGUSER ?? 'postgres'}:${process.env.PGPASSWORD ?? 'payload'}@${process.env.PGHOST ?? 'localhost'}:${process.env.PGPORT ?? '5433'}/${dbName}`

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  // One seeded-admin login per run (concurrent logins race).
  globalSetup: './admin-session.ts',
  // Payload line under test: keys the a11y upstream snapshot (a11y.spec.ts).
  metadata: { payloadMajor: 3 },
  fullyParallel: false,
  // Postgres + cold Turbopack: migrations push on first hit, so the
  // first tests pay extra.
  timeout: 120_000,
  expect: { timeout: 20_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:3102',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'cd ../examples/basic && bun run dev:e2e-pg',
    url: 'http://localhost:3102',
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    env: {
      PAYLOAD_DB: 'postgres',
      DATABASE_URL: databaseUrl,
      ...DEV_ADMIN_SEED_ENV,
    },
  },
})
