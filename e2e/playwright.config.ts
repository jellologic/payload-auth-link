import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  // One seeded-admin login per run (concurrent logins race).
  globalSetup: './admin-session.ts',
  fullyParallel: false,
  // Cold Turbopack compiles (Payload admin, auth routes) are slow: the
  // server is warm after the first hits, but early tests pay for it.
  timeout: 90_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:3101',
    trace: 'retain-on-failure',
  },
  // The sqlite matrix runs all three engines: cookie and redirect
  // handling differ across Chromium, Gecko, and WebKit (TST-8). The
  // postgres and mongo matrices stay Chromium-only (CI budget).
  // Engines run one after another (`dependencies`), never concurrently:
  // they share one server and one seeded admin, and concurrent admin
  // logins race on Payload's per-user sessions array (one login's
  // write drops the other's session → spurious 403s).
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, dependencies: ['chromium'] },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, dependencies: ['firefox'] },
  ],
  webServer: {
    command: 'cd ../examples/basic && rm -f payload.db* && bun run dev:e2e',
    url: 'http://localhost:3101',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    env: { ...DEV_ADMIN_SEED_ENV },
  },
})
