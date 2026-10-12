import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'

// TanStack Postgres parity run: same 18 specs, same example,
// `PAYLOAD_DB=postgres`. A per-run database name keeps every run on a
// fresh schema (the adapter creates it on connect); CI points PGHOST
// at its service.
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
  fullyParallel: false,
  // Postgres + cold Vite SSR: schema push on first hit, so the first
  // tests pay extra.
  timeout: 120_000,
  expect: { timeout: 20_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:3202',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'cd ../examples/tanstack-start && bun run dev:e2e-pg',
    url: 'http://localhost:3202',
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    env: {
      PAYLOAD_DB: 'postgres',
      DATABASE_URL: databaseUrl,
      ...DEV_ADMIN_SEED_ENV,
    },
  },
})
