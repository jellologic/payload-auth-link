import { defineConfig } from 'vitest/config'

/**
 * Migration-kit suites (fixtures/): Postgres-only tests against the
 * payload-auth fixture dump (issue #59). Excluded from the default
 * `vitest.config.ts` (which must stay adapter-free); CI runs this
 * config in the `migration-fixture` job. Locally: docker start pal-pg.
 */
export default defineConfig({
  test: {
    include: ['fixtures/*/test/**/*.test.ts'],
    // Loading the dump and (later) booting Payload against it is slow.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // One database per file; files never share state.
    fileParallelism: false,
  },
})
