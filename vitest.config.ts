import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // payload-auth's dist uses directory imports (`export * from
    // "./better-auth"`), which Bun tolerates and Node's ESM loader does
    // not; the doctor loads real payload-auth configs, so vitest must
    // transform the package instead of externalizing it. The UI
    // component chain is inlined for the same reason: externalized,
    // its CSS imports (`react-image-crop`'s stylesheet via
    // `@payloadcms/ui`) reach the raw runtime loader, which fails with
    // `Unknown file extension ".css"` on some Node versions — inlined,
    // Vite handles (and with `css: false`, stubs) them.
    server: { deps: { inline: [/payload-auth/, /@payloadcms[+]ui/, /react-image-crop/] } },
    css: false,
    exclude: [
      'packages/migrate/src/__tests__/adopt-boot.test.ts',
      'packages/migrate/src/__tests__/importer.test.ts',
      'packages/migrate/src/__tests__/exporters.test.ts',
      'packages/migrate/src/__tests__/cli-lifecycle.test.ts',
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
        // The whole migration kit is database-bound (doctor
        // introspection, importer lifecycle, CLI) and is proven
        // against the payload-auth fixture in the migration-fixture
        // CI job (live Postgres; `check` stays service-free).
        'packages/migrate/src/**',
        // The conformance kit's violation branches are exercised by
        // the dedicated provider-conformance tests' failing fixtures;
        // v8 attributes them to the kit file itself.
        'packages/core/src/testing/**',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
        // Per-file floors for every auth-critical file (issue #86): the
        // global 80% would let session verification, the strategy, the
        // account gates, the server API, and the provider adapters
        // regress unnoticed behind well-covered files. Target 95%
        // everywhere; a floor below 95 is the measured value rounded
        // down, and docs/coverage-exceptions.md lists the uncovered
        // branches and why. Raise floors as coverage improves — never
        // lower one without updating that doc.
        'packages/core/src/cookies.ts': { lines: 95, functions: 95, branches: 95, statements: 95 },
        'packages/plugin/src/access.ts': { lines: 95, functions: 95, branches: 95, statements: 95 },
        'packages/plugin/src/audit.ts': { lines: 95, functions: 91, branches: 88, statements: 95 },
        'packages/plugin/src/collections.ts': {
          lines: 95,
          functions: 95,
          branches: 86,
          statements: 95,
        },
        'packages/plugin/src/compat-shim.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/plugin/src/endpoints.ts': {
          lines: 95,
          functions: 95,
          branches: 91,
          statements: 95,
        },
        'packages/plugin/src/organizations.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/plugin/src/repository.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/plugin/src/server.ts': { lines: 95, functions: 95, branches: 94, statements: 95 },
        'packages/plugin/src/session.ts': {
          lines: 95,
          functions: 95,
          branches: 94,
          statements: 95,
        },
        'packages/plugin/src/strategy.ts': {
          lines: 95,
          functions: 95,
          branches: 86,
          statements: 95,
        },
        'packages/provider-authjs/src/port.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/provider-better-auth/src/adapter.ts': {
          lines: 80,
          functions: 91,
          branches: 73,
          statements: 81,
        },
        'packages/provider-better-auth/src/cookies.ts': {
          lines: 95,
          functions: 95,
          branches: 89,
          statements: 95,
        },
        'packages/provider-better-auth/src/port.ts': {
          lines: 86,
          functions: 86,
          branches: 77,
          statements: 86,
        },
        'packages/provider-better-auth/src/session-provenance.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/provider-better-auth/src/where.ts': {
          lines: 95,
          functions: 95,
          branches: 95,
          statements: 95,
        },
        'packages/web/src/authz.ts': { lines: 95, functions: 95, branches: 95, statements: 95 },
        'packages/web/src/verify.ts': { lines: 95, functions: 95, branches: 95, statements: 95 },
      },
    },
  },
})
