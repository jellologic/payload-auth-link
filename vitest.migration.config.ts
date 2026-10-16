import { defineConfig } from 'vitest/config'

import { packageDependencyInline } from './vitest.shared.js'

/**
 * Migration-kit suites (fixtures/): Postgres-only tests against the
 * payload-auth fixture dump (issue #59). Excluded from the default
 * `vitest.config.ts` (which must stay adapter-free); CI runs this
 * config in the `migration-fixture` job. Locally: docker start pal-pg.
 */
export default defineConfig({
  test: {
    include: [
      'fixtures/*/test/**/*.test.ts',
      // The migration kit's own Postgres-backed suites.
      'packages/migrate/src/__tests__/adopt-boot.test.ts',
      'packages/migrate/src/__tests__/importer.test.ts',
      'packages/migrate/src/__tests__/exporters.test.ts',
      'packages/migrate/src/__tests__/cli-lifecycle.test.ts',
    ],
    // payload-auth's dist uses directory imports Bun tolerates and
    // Node's loader does not; tests that import its modules need the
    // transform (the main vitest.config.ts sets the same). Anchored to
    // the installed package: a bare `/payload-auth/` also matched the
    // checkout path itself (issue #110).
    server: { deps: { inline: [packageDependencyInline('payload-auth')] } },
    // Loading the dump and (later) booting Payload against it is slow.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // One database per file; files never share state.
    fileParallelism: false,
  },
})
