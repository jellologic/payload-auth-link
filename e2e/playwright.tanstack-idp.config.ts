import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'
import { MOCK_IDP_ORIGIN, MOCK_IDP_PORT } from './idp-helpers.js'

// TanStack Start twin of `playwright.idp.config.ts`: the same
// `idp-*.e2e.ts` specs against the external-IdP variant of
// examples/tanstack-start (`E2E_MOCK_IDP`, see its src/lib/e2e-idp.ts),
// on its own port and SQLite file (`src/payload-idp.db`), with the
// local mock OIDC provider as the first webServer.
export default defineConfig({
  testDir: '.',
  testMatch: 'idp-*.e2e.ts',
  // One seeded-admin login per run (organizations, role grants).
  globalSetup: './admin-session.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:3205',
    trace: 'retain-on-failure',
  },
  // CI runs Chromium then WebKit (`--project=chromium --project=webkit`);
  // Firefox chains last for local cross-engine runs. Engines run one
  // after another for the shared-admin reason in the main config.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, dependencies: ['chromium'] },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, dependencies: ['webkit'] },
  ],
  webServer: [
    {
      command: 'bun mock-idp.ts',
      url: `${MOCK_IDP_ORIGIN}/.well-known/openid-configuration`,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
      env: { MOCK_IDP_PORT: String(MOCK_IDP_PORT) },
    },
    {
      command: 'cd ../examples/tanstack-start && rm -f src/payload-idp.db* && bun run dev:e2e-idp',
      url: 'http://localhost:3205',
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      env: { ...DEV_ADMIN_SEED_ENV },
    },
  ],
})
