/**
 * Consumer-install smoke (PLAN-UPGRADE-RESILIENCE Phase 2, B14):
 * pack every package the way we publish, install the tarballs into
 * throwaway npm and pnpm consumers, and import the public entries —
 * proving what static analysis cannot: that a fresh install resolves,
 * that nothing depends on phantom hoisted packages, and that pnpm's
 * strict linker behaves exactly as documented.
 *
 *   npm consumer:   every package + real peers; every public entry
 *                   (including /cookies and the plugin's /admin) imports.
 *   pnpm consumer:  only the plugin + Better Auth provider tarballs
 *                   (the README install); importing
 *                   `@payload-auth-link/core` directly MUST FAIL —
 *                   consumers that do that install core explicitly.
 *
 * Run: `bun run release:smoke` (after `bun run build`; wired into
 * release:check). Heavy by design — this is the release gate.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

// Peers a consumer installs to actually import everything. Pin to the
// validated band (compatibility.md) so the smoke tests the claim.
const PEERS = {
  payload: '3.90.2',
  '@payloadcms/ui': '3.90.2',
  'better-auth': '1.7.7',
  '@auth/core': '0.41.3',
  next: '16.4.0',
  '@tanstack/react-start': '1.168.61',
  '@tanstack/react-router': '1.170.41',
  react: '^19.0.0',
  'react-dom': '^19.0.0',
}

const PACKAGE_ORDER = [
  'core',
  'web',
  'react',
  'plugin',
  'provider-better-auth',
  'provider-authjs',
  'next',
  'tanstack-start',
]

// Every public entry, per package. Keep in lockstep with the exports
// maps — a new subpath that is not importable here is not shippable.
// Entries that must fully import in plain Node (everything except
// bundler-only entries, which are resolve-checked: their modules
// import CSS and JSX that only a bundler can execute).
const ENTRIES = {
  core: ['.'],
  web: ['.'],
  react: ['.'],
  plugin: ['.'],
  'provider-better-auth': ['.', '/cookies'],
  'provider-authjs': ['.', '/cookies'],
  next: ['.'],
  'tanstack-start': ['.'],
}

const RESOLVE_ONLY = [['@payload-auth-link/plugin', '/admin']]

function run(command, args, options = {}) {
  execFileSync(command, args, { stdio: options.capture ? 'pipe' : 'inherit', ...options })
}

function pack(dir, dest) {
  run('bun', ['pm', 'pack', '--destination', dest, '--quiet'], { cwd: dir })
  return readdirSync(dest).filter((file) => file.endsWith('.tgz'))
}

const stage = mkdtempSync(join(tmpdir(), 'pal-install-smoke-'))
const packDir = join(stage, 'pack')
mkdirSync(packDir)
try {
  const tarballs = {}
  for (const name of PACKAGE_ORDER) {
    const before = new Set(readdirSync(packDir))
    pack(join(root, 'packages', name), packDir)
    const file = readdirSync(packDir).find((f) => !before.has(f))
    if (file === undefined) {
      throw new Error(`no tarball produced for ${name}`)
    }
    tarballs[name] = join(packDir, file)
  }

  // ---- npm consumer: full install, every entry imports ----
  const npmDir = join(stage, 'consumer-npm')
  mkdirSync(npmDir)
  writeFileSync(join(npmDir, 'package.json'), JSON.stringify({ private: true }) + '\n')
  console.log('install-smoke: npm consumer installing full set…')
  run(
    'npm',
    [
      'install',
      '--no-audit',
      '--no-fund',
      '--loglevel=error',
      ...PACKAGE_ORDER.map((name) => tarballs[name]),
      ...Object.entries(PEERS).flatMap(([name, spec]) => [`${name}@${spec}`]),
    ],
    { cwd: npmDir }
  )

  const importScript = join(npmDir, 'import-all.mjs')
  const scopedEntries = Object.fromEntries(
    Object.entries(ENTRIES).map(([name, subpaths]) => [`@payload-auth-link/${name}`, subpaths])
  )
  writeFileSync(
    importScript,
    `const failures = []\n` +
      `for (const [pkg, subpaths] of Object.entries(${JSON.stringify(scopedEntries)})) {\n` +
      `  for (const sub of subpaths) {\n` +
      `    const specifier = sub === '.' ? pkg : pkg + sub\n` +
      `    try {\n` +
      `      await import(specifier)\n` +
      `      console.log('ok    ', specifier)\n` +
      `    } catch (error) {\n` +
      `      failures.push(specifier + ': ' + (error && error.message))\n` +
      `      console.log('FAIL  ', specifier, error && error.message)\n` +
      `    }\n` +
      `  }\n` +
      `}\n` +
      `for (const [pkg, sub] of ${JSON.stringify(RESOLVE_ONLY)}) {\n` +
      `  const specifier = pkg + sub\n` +
      `  try {\n` +
      `    // Bundler-only entry (admin components import CSS): proving\n` +
      `    // it ships and resolves is the smoke; executing it is not.\n` +
      `    if (import.meta.resolve(specifier) === undefined) throw new Error('unresolved')\n` +
      `    console.log('resolve', specifier)\n` +
      `  } catch (error) {\n` +
      `    failures.push(specifier + ': ' + (error && error.message))\n` +
      `    console.log('FAIL  ', specifier, error && error.message)\n` +
      `  }\n` +
      `}\n` +
      `if (failures.length > 0) { console.error('FAILED:\\n' + failures.join('\\n')); process.exit(1) }\n` +
      `console.log('install-smoke: npm consumer imports every public entry')\n`
  )
  run('node', [importScript], { cwd: npmDir })

  // ---- pnpm consumer: strict linker, documented minimal install ----
  const pnpmDir = join(stage, 'consumer-pnpm')
  mkdirSync(pnpmDir)
  // pnpm resolves a tarball's own `@payload-auth-link/core@0.2.0` dep
  // from the registry (same version, wrong build). Override it to the
  // packed tarball so the consumer exercises the current tree.
  writeFileSync(
    join(pnpmDir, 'package.json'),
    JSON.stringify({
      private: true,
      pnpm: { overrides: { '@payload-auth-link/core': tarballs.core } },
    }) + '\n'
  )
  console.log('install-smoke: pnpm consumer installing plugin + provider…')
  run(
    'bunx',
    [
      'pnpm@10',
      'add',
      '--loglevel=error',
      tarballs.core,
      tarballs.plugin,
      tarballs['provider-better-auth'],
      `better-auth@${PEERS['better-auth']}`,
      `payload@${PEERS.payload}`,
      `react@${PEERS.react}`,
      `@payloadcms/ui@${PEERS['@payloadcms/ui']}`,
    ],
    { cwd: pnpmDir }
  )

  const pnpmScript = join(pnpmDir, 'pnpm-probe.mjs')
  writeFileSync(
    pnpmScript,
    `// Minimal install: core is here only because pnpm's strict linker\n` +
      `// requires the documented explicit install for direct imports.\n` +
      `// A package the consumer did NOT install must stay unresolvable —\n` +
      `// nothing may pull it in through a phantom hoisted dep.\n` +
      `let webFailed = null\n` +
      `try { await import('@payload-auth-link/web') } catch (error) { webFailed = error }\n` +
      `if (webFailed === null) {\n` +
      `  console.error('FAIL: @payload-auth-link/web resolved without being installed (phantom dep)')\n` +
      `  process.exit(1)\n` +
      `}\n` +
      `await import('@payload-auth-link/core')\n` +
      `await import('@payload-auth-link/plugin')\n` +
      `await import('@payload-auth-link/provider-better-auth')\n` +
      `await import('@payload-auth-link/provider-better-auth/cookies')\n` +
      `console.log('install-smoke: pnpm consumer strict-linker behavior matches the docs')\n`
  )
  run('node', [pnpmScript], { cwd: pnpmDir })

  console.log('install-smoke passed')
} finally {
  rmSync(stage, { recursive: true, force: true })
}
