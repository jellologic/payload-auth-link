import { defineConfig, devices } from '@playwright/test'

// SEC-7 proof: both examples boot on fresh SQLite databases WITHOUT
// `ALLOW_DEV_ADMIN_SEED`, and `seed-gate.e2e.ts` asserts no dev admin
// exists while the app stays healthy. Deliberately outside the six
// matrix configs (which set the flag): this file is matched only here.
export default defineConfig({
  testDir: '.',
  testMatch: 'seed-gate.e2e.ts',
  fullyParallel: false,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  projects: [
    { name: 'next', use: { ...devices['Desktop Chrome'], baseURL: 'http://localhost:3111' } },
    { name: 'tanstack', use: { ...devices['Desktop Chrome'], baseURL: 'http://localhost:3211' } },
  ],
  webServer: [
    {
      command:
        'cd ../examples/basic && rm -f payload.db* && EXAMPLE_BASE_URL=http://localhost:3111 bunx next dev -p 3111',
      url: 'http://localhost:3111',
      reuseExistingServer: !process.env.CI,
      timeout: 240_000,
    },
    {
      command:
        'cd ../examples/tanstack-start && rm -f src/payload.db* && EXAMPLE_BASE_URL=http://localhost:3211 bunx vite dev --port 3211',
      url: 'http://localhost:3211',
      reuseExistingServer: !process.env.CI,
      timeout: 240_000,
    },
  ],
})
