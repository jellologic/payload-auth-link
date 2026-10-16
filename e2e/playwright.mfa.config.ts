import { defineConfig, devices } from '@playwright/test'
import { DEV_ADMIN_SEED_ENV } from './dev-admin.js'

// `policies.requireMfaForRoles` (CAP-6) against a Better-Auth-only
// variant of examples/basic (`E2E_MFA_POLICY=1`, see its
// payload.config.ts): the policy throws at wiring unless every provider
// declares `mfa`, and the default examples also register Auth.js. Own
// port and own SQLite file (`payload-mfa.db`), so it never shares a
// database with the default suite; matched only here (`*.e2e.ts` is
// outside the matrix configs' `*.spec.ts`). Like the postgres/mongo
// configs it runs the same Next project directory, so do not run it
// concurrently with another `next dev` of examples/basic.
export default defineConfig({
  testDir: '.',
  testMatch: 'mfa-policy.e2e.ts',
  // One seeded-admin login per run (grants the gated role).
  globalSetup: './admin-session.ts',
  fullyParallel: false,
  // Better Auth's `twoFactor()` throttles `/two-factor/*` to 3 requests
  // per 10s per IP (all local runs share one IP): parallel TOTP flows
  // would only fight over that bucket.
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:3104',
    trace: 'retain-on-failure',
  },
  // CI runs Chromium only; WebKit is here for local cross-engine runs.
  // Sequential (`dependencies`) for the same shared-admin reason as the
  // main config.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, dependencies: ['chromium'] },
  ],
  webServer: {
    command: 'cd ../examples/basic && rm -f payload-mfa.db* && bun run dev:e2e-mfa',
    url: 'http://localhost:3104',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
    env: { ...DEV_ADMIN_SEED_ENV },
  },
})
