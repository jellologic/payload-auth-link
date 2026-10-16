import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import globals from 'globals'

const workspaceSiblings = ['@payload-auth-link/*']

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '.claude/**',
      'docs/api/**',
      '**/node_modules/**',
      '**/.next/**',
      'coverage/**',
      'playwright-report/**',
      'test-results/**',
      '**/importMap.js',
      '**/payload-types.ts',
      '**/next-env.d.ts',
      // ARCH-2: boundary-violation fixtures must fail lint, so they are
      // ignored by the normal run and executed explicitly by their tests.
      '**/__fixtures__/**',
      // B19: the consumer fixture typechecks built dist types under its
      // own tsconfig (skipLibCheck off); it is not part of any lint project.
      'scripts/consumer-fixture/**',
      // The payload-auth fixture mirrors a THIRD-PARTY app layout
      // (payload-auth 1.9.4 + Better Auth 1.6) that our lint rules
      // would reject on sight; it is a generator for the committed
      // dump, not shipped code. It stays prettier-formatted, runs only
      // through the migration CI job, and imports no workspace code.
      'fixtures/**',
      'snapshots/**',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          // The web lint fixture is excluded from its tsconfig (it must
          // not compile); the default project keeps the explicit
          // `--no-ignore` fixture run from failing on type info instead
          // of the boundary rule under test.
          allowDefaultProject: [
            'vitest.config.ts',
            'vitest.migration.config.ts',
            'packages/web/src/__fixtures__/*.ts',
          ],
        },
        tsconfigRootDir: import.meta.dirname,
      },
      globals: { ...globals.node, ...globals.browser },
    },
  },
  reactHooks.configs.flat.recommended,
  jsxA11y.flatConfigs.recommended,
  {
    files: ['**/*.mjs', '**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  // core imports no framework and no workspace siblings.
  {
    files: ['packages/core/src/**/*'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'payload', message: 'core is framework-free.' },
            { name: 'react', message: 'core is framework-free.' },
            { name: 'react-dom', message: 'core is framework-free.' },
            { name: 'next', message: 'core is framework-free.' },
          ],
          patterns: [
            { group: ['next/*'], message: 'core is framework-free.' },
            { group: ['@payloadcms/*'], message: 'core is framework-free.' },
            { group: workspaceSiblings, message: 'core depends on nothing.' },
          ],
        },
      ],
    },
  },
  // web is the framework-free web surface: core plus relative imports
  // only. No test exemption: the web suites compose core alone.
  {
    files: ['packages/web/src/**/*'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'payload', message: 'web is framework-free: core plus relative imports only.' },
            { name: 'react', message: 'web is framework-free: core plus relative imports only.' },
            {
              name: 'react-dom',
              message: 'web is framework-free: core plus relative imports only.',
            },
            { name: 'next', message: 'web is framework-free: core plus relative imports only.' },
          ],
          patterns: [
            {
              group: ['next/*'],
              message: 'web is framework-free: core plus relative imports only.',
            },
            {
              group: ['@tanstack/*'],
              message: 'web is framework-free: core plus relative imports only.',
            },
            {
              group: ['@payloadcms/*'],
              message: 'web is framework-free: core plus relative imports only.',
            },
            {
              group: [
                '@payload-auth-link/plugin',
                '@payload-auth-link/react',
                '@payload-auth-link/next',
                '@payload-auth-link/web',
                '@payload-auth-link/tanstack-start',
                '@payload-auth-link/provider-*',
              ],
              message: 'web depends on core only.',
            },
          ],
        },
      ],
    },
  },
  // react imports no Next and no Payload.
  {
    files: ['packages/react/src/**/*'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'payload', message: 'react imports no Payload.' },
            { name: 'next', message: 'react imports no Next.' },
          ],
          patterns: [
            { group: ['next/*'], message: 'react imports no Next.' },
            { group: ['@payloadcms/*'], message: 'react imports no Payload.' },
            {
              group: [
                '@payload-auth-link/plugin',
                '@payload-auth-link/next',
                '@payload-auth-link/tanstack-start',
                '@payload-auth-link/provider-*',
              ],
              message: 'react sits below framework adapters.',
            },
          ],
        },
      ],
    },
  },
  // plugin imports no React outside admin/.
  {
    files: ['packages/plugin/src/**/*.ts', 'packages/plugin/src/**/*.tsx'],
    ignores: ['packages/plugin/src/admin/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'react', message: 'plugin imports React only in admin/.' },
            { name: 'react-dom', message: 'plugin imports React only in admin/.' },
            { name: 'next', message: 'plugin imports no Next.' },
          ],
          patterns: [
            { group: ['next/*'], message: 'plugin imports no Next.' },
            {
              group: [
                '@payload-auth-link/react',
                '@payload-auth-link/next',
                '@payload-auth-link/tanstack-start',
              ],
              message: 'plugin sits below UI adapters.',
            },
          ],
        },
      ],
    },
  },
  // framework adapters may use framework types but never Payload runtimes.
  // Integration tests are exempt: they must compose the real plugin runtime to prove interop.
  {
    files: ['packages/next/src/**/*'],
    ignores: ['packages/next/src/**/__tests__/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'payload',
              message: 'adapters take clients by injection; no runtime payload import.',
              allowTypeImports: true,
            },
          ],
          patterns: [
            {
              group: ['@payload-auth-link/plugin'],
              message: 'adapters sit beside the plugin, never above it.',
            },
            {
              // Next ships no `exports` map: an extension-less subpath
              // resolves under bundlers but crashes plain Node ESM
              // (ERR_MODULE_NOT_FOUND) for every consumer of `dist`.
              regex: '^next/(?!.*\\.js$).+',
              message:
                "import Next subpaths with '.js' (e.g. 'next/headers.js') so dist runs under plain Node.",
            },
          ],
        },
      ],
    },
  },
  // TanStack Start adapter: mirrors the Next block.
  {
    files: ['packages/tanstack-start/src/**/*'],
    ignores: ['packages/tanstack-start/src/**/__tests__/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'payload',
              message: 'adapters take clients by injection; no runtime payload import.',
              allowTypeImports: true,
            },
          ],
          patterns: [
            {
              group: ['@payload-auth-link/plugin'],
              message: 'adapters sit beside the plugin, never above it.',
            },
          ],
        },
      ],
    },
  },
  // providers are framework-free: no React, Next, or TanStack surface,
  // including Better Auth's framework cookie plugins (ARCH-1: builders
  // declare those in their own options.plugins, never the engine).
  {
    files: ['packages/provider-*/src/**/*'],
    ignores: ['packages/provider-*/src/**/__tests__/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'payload',
              message: 'providers take clients by injection; no runtime payload import.',
              allowTypeImports: true,
            },
            { name: 'react', message: 'providers are framework-free.' },
            { name: 'react-dom', message: 'providers are framework-free.' },
            { name: 'next', message: 'providers are framework-free.' },
            {
              name: 'better-auth/next-js',
              message: 'cookie plugins are builder-declared, never engine-owned.',
            },
            {
              name: 'better-auth/tanstack-start',
              message: 'cookie plugins are builder-declared, never engine-owned.',
            },
          ],
          patterns: [
            { group: ['next/*'], message: 'providers are framework-free.' },
            { group: ['@tanstack/*'], message: 'providers are framework-free.' },
            {
              group: ['@payload-auth-link/plugin'],
              message: 'providers sit beside the plugin, never above it.',
            },
          ],
        },
      ],
    },
  }
)
