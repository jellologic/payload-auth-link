/**
 * Shared Vitest resolution helpers for `vitest.config.ts` and
 * `vitest.migration.config.ts` (issue #110).
 */

/**
 * A `server.deps.inline` pattern for ONE installed package. It matches
 * the package's own directory under any `node_modules` (flat installs
 * and Bun's isolated `.bun/<pkg>@<version>/node_modules/<pkg>/` store
 * alike) and nothing else: never a checkout whose path merely contains
 * the name, and never a package whose name only starts with it.
 */
export function packageDependencyInline(name: string): RegExp {
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
  return new RegExp(`[\\\\/]node_modules[\\\\/]${escaped.replace('\\/', '[\\\\/]')}[\\\\/]`)
}

/** Workspace subpath exports, as published path → source path under `src/`. */
const SUBPATH_SOURCES: Readonly<Record<string, string>> = {
  'core/testing': 'core/src/testing/index.ts',
  'plugin/admin': 'plugin/src/admin/index.ts',
  'provider-authjs/cookies': 'provider-authjs/src/cookies.ts',
  'provider-better-auth/cookies': 'provider-better-auth/src/cookies.ts',
}

/**
 * Aliases that resolve every `@payload-auth-link/*` import to the
 * workspace package's SOURCE entry instead of its built `dist`, so a
 * test that imports a sibling package by name runs (and is measured
 * on) the code under `packages/<name>/src`.
 */
export function workspaceSourceAliases(repoRoot: string): { find: RegExp; replacement: string }[] {
  const packages = `${repoRoot.replace(/[\\/]$/, '')}/packages`
  return [
    ...Object.entries(SUBPATH_SOURCES).map(([subpath, source]) => ({
      find: new RegExp(`^@payload-auth-link/${subpath}$`),
      replacement: `${packages}/${source}`,
    })),
    { find: /^@payload-auth-link\/([a-z-]+)$/, replacement: `${packages}/$1/src/index.ts` },
  ]
}
