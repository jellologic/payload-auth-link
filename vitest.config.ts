import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // payload-auth's dist uses directory imports (`export * from
    // "./better-auth"`), which Bun tolerates and Node's ESM loader does
    // not; the doctor loads real payload-auth configs, so vitest must
    // transform the package instead of externalizing it.
    server: { deps: { inline: [/payload-auth/] } },
    exclude: [
      'packages/migrate/src/__tests__/adopt-boot.test.ts',
      'packages/migrate/src/__tests__/importer.test.ts',
    ],
    include: [
      'packages/*/src/**/*.test.ts',
      'packages/*/src/**/*.test.tsx',
      // Example-owned reference patterns (rate limiter) carry their own
      // deterministic tests; coverage stays packages-only below.
      'examples/basic/lib/**/*.test.ts',
      'examples/tanstack-start/src/lib/**/*.test.ts',
      // Release tooling contracts (publish output, tagging).
      'scripts/**/*.test.mjs',
    ],
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.ts', 'packages/*/src/**/*.tsx'],
      exclude: [
        '**/__tests__/**',
        '**/*.test.*',
        '**/__fixtures__/**',
        // The migration kit's database-bound code (the doctor's
        // introspection and the importer) is proven against the
        // payload-auth fixture in the migration-fixture CI job (it
        // needs a live Postgres; `check` stays service-free).
        'packages/migrate/src/doctor/database.ts',
        'packages/migrate/src/importer/**',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
        // Per-file floors for the auth core: the global 80% would let
        // session verification, the Payload strategy, and the user
        // store regress unnoticed behind well-covered files. Set just
        // under the measured values; raise them as coverage improves.
        'packages/plugin/src/session.ts': {
          lines: 90,
          functions: 90,
          branches: 85,
          statements: 90,
        },
        'packages/plugin/src/strategy.ts': {
          lines: 95,
          functions: 95,
          branches: 85,
          statements: 95,
        },
        'packages/plugin/src/repository.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/plugin/src/endpoints.ts': {
          lines: 90,
          functions: 90,
          branches: 85,
          statements: 90,
        },
      },
    },
  },
})
