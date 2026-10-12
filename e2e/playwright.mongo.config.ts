import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'

// Mongo parity run: same specs, same example, `PAYLOAD_DB=mongo`.
// MONGODB_URI comes from the `e2e:mongo` wrapper (per-run replset);
// failing fast here beats a cryptic adapter error later.
const uri = process.env.MONGODB_URI
if (!uri) {
  throw new Error('playwright.mongo.config.ts requires MONGODB_URI (run via bun run e2e:mongo)')
}

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  timeout: 120_000,
  expect: { timeout: 20_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:3103',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'cd ../examples/basic && bun run dev:e2e-mongo',
    url: 'http://localhost:3103',
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    env: {
      PAYLOAD_DB: 'mongo',
      MONGODB_URI: uri,
      ...DEV_ADMIN_SEED_ENV,
    },
  },
})
