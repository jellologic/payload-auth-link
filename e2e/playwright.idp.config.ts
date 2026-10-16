import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'
import { MOCK_IDP_ORIGIN, MOCK_IDP_PORT } from './idp-helpers.js'

// External-IdP variant of examples/basic (`E2E_MOCK_IDP`, see
// examples/basic/lib/e2e-idp.ts): social OAuth, One Tap, phone, SSO
// domains, multi-session, roleValues, and reqUser against a local mock
// OIDC provider (`mock-idp.ts`, the first webServer). Own port and own
// SQLite file (`payload-idp.db`): the variant changes stored data
// shapes and makes Auth.js an SSO provider, so it never shares a
// database with the default suite. Matched only here and in the
// TanStack twin (`*.e2e.ts` is outside the matrix configs'
// `*.spec.ts`). It runs the same Next project directory as the
// default config, so do not run it concurrently with another
// `next dev` of examples/basic.
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
    baseURL: 'http://localhost:3105',
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
      command: 'cd ../examples/basic && rm -f payload-idp.db* && bun run dev:e2e-idp',
      url: 'http://localhost:3105',
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      env: { ...DEV_ADMIN_SEED_ENV },
    },
  ],
})
