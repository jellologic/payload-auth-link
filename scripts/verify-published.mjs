/**
 * Prove a published release from the outside, as a consumer sees it.
 *
 *   bun run verify:published 0.1.1 [--expect-provenance]
 *
 * For every package at <version>, against the live npm registry:
 *   1. the version is served, and sibling dependency ranges are real
 *      versions (no `workspace:` leak);
 *   2. with --expect-provenance, the version carries a SLSA provenance
 *      attestation (published by CI through trusted publishing);
 *   3. a fresh consumer project installs every package plus the peers it
 *      declares, and `npm audit signatures` verifies registry signatures
 *      (and attestations, when present);
 *   4. every entry point (including subpaths) imports under plain Node
 *      ESM;
 *   5. a consumer TypeScript file type-checks against the published
 *      declarations.
 *
 * Exits non-zero on the first failed proof.
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const version = process.argv[2]
const expectProvenance = process.argv.includes('--expect-provenance')
// Releases mix version lines (minors vs patches); `--only a,b` scopes a
// run to those packages so each line can be verified separately:
//   bun run verify:published 0.3.0 --expect-provenance --only core,plugin
const onlyIndex = process.argv.indexOf('--only')
const only = onlyIndex === -1 ? null : (process.argv[onlyIndex + 1] ?? '').split(',')
if (version === undefined || !/^\d+\.\d+\.\d+/.test(version)) {
  throw new Error('usage: bun run verify:published <version> [--expect-provenance] [--only a,b]')
}

const allNames = [
  'core',
  'web',
  'react',
  'plugin',
  'next',
  'tanstack-start',
  'provider-better-auth',
  'provider-authjs',
  'migrate',
]

function step(label) {
  process.stdout.write(`\n== ${label}\n`)
}

async function registry(path) {
  const response = await fetch(`https://registry.npmjs.org/${path}`, {
    headers: { 'cache-control': 'no-cache' },
  })
  if (!response.ok) {
    throw new Error(`registry ${path}: HTTP ${response.status}`)
  }
  return response.json()
}

step(`1-2. registry manifests for ${version}`)
const peers = new Map()
const entryPoints = []
const names = only === null ? allNames : allNames.filter((name) => only.includes(name))
if (names.length === 0) {
  throw new Error(`--only matched no package (have: ${allNames.join(', ')})`)
}
// The web consumer snippet type-checks against core helpers. A
// release line can carry web without core (patch lines), so the type
// step installs core@latest as a helper — provenance is still
// asserted only for `names` at the given version.
const typeNames = names.includes('web') && !names.includes('core') ? ['core', ...names] : names
const helperDeps = typeNames.length > names.length ? ['@payload-auth-link/core@latest'] : []
for (const name of names) {
  const id = `@payload-auth-link/${name}`
  const manifest = await registry(`${id.replace('/', '%2f')}/${version}`)
  const ranges = { ...manifest.dependencies, ...manifest.peerDependencies }
  const leaked = Object.entries(ranges).filter(([, range]) => String(range).includes('workspace:'))
  if (leaked.length > 0) {
    throw new Error(`${id}@${version} leaks workspace ranges: ${JSON.stringify(leaked)}`)
  }
  const attestations = manifest.dist?.attestations
  if (expectProvenance && attestations?.provenance === undefined) {
    throw new Error(`${id}@${version} has no provenance attestation`)
  }
  for (const [peer, range] of Object.entries(manifest.peerDependencies ?? {})) {
    peers.set(peer, range)
  }
  for (const subpath of Object.keys(manifest.exports ?? { '.': null })) {
    entryPoints.push(subpath === '.' ? id : `${id}/${subpath.replace(/^\.\//, '')}`)
  }
  process.stdout.write(
    `ok ${id}@${version}${attestations?.provenance ? ' (provenance attested)' : ''}\n`
  )
}

step('3. fresh consumer install + npm audit signatures')
const consumer = mkdtempSync(join(tmpdir(), 'pal-consumer-'))
const run = (command, args) =>
  execFileSync(command, args, { cwd: consumer, stdio: 'inherit', env: process.env })
writeFileSync(
  join(consumer, 'package.json'),
  JSON.stringify({ name: 'pal-consumer', private: true, type: 'module' }, null, 2)
)
// Peer ranges like `^3.0.0 || ^4.0.0-beta.0` resolve to the stable line.
const peerSpecs = [...peers.keys()].map((peer) => (peer === 'react' ? 'react@19' : peer))
run('npm', [
  'install',
  '--no-audit',
  '--no-fund',
  ...names.map((name) => `@payload-auth-link/${name}@${version}`),
  ...helperDeps,
  ...peerSpecs,
  'react-dom@19',
  'typescript@5',
  '@types/react@19',
])
run('npm', ['audit', 'signatures'])

step(`4. import every entry point (${entryPoints.length})`)
// Bundler-only entries pull CSS through @payloadcms/ui, which plain Node
// cannot evaluate (Payload loads them through Next/Vite). For those,
// prove resolution of the entry and every bare import it ships instead.
const bundlerOnly = ['@payload-auth-link/plugin/admin']
writeFileSync(
  join(consumer, 'imports.mjs'),
  `import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
const ids = ${JSON.stringify(entryPoints)}
const bundlerOnly = new Set(${JSON.stringify(bundlerOnly)})
for (const id of ids) {
  if (bundlerOnly.has(id)) {
    const source = readFileSync(fileURLToPath(import.meta.resolve(id)), 'utf8')
    for (const [, spec] of source.matchAll(/from\\s*['"]([^'"./][^'"]*)['"]/g)) import.meta.resolve(spec)
    continue
  }
  const mod = await import(id)
  if (Object.keys(mod).length === 0) throw new Error('entry point with no exports: ' + id)
}
console.log('verified ' + ids.length + ' entry points (' + bundlerOnly.size + ' by resolution)')
`
)
run('node', ['imports.mjs'])

step('5. type-check a consumer against the published declarations')
writeFileSync(
  join(consumer, 'tsconfig.json'),
  JSON.stringify(
    {
      compilerOptions: {
        target: 'es2022',
        module: 'nodenext',
        moduleResolution: 'nodenext',
        strict: true,
        noEmit: true,
        skipLibCheck: true,
        jsx: 'react-jsx',
      },
      files: ['consumer.ts'],
    },
    null,
    2
  )
)
// Per-package consumer snippets; a --only run type-checks only the
// packages it installed.
const consumerSnippets = {
  core: {
    imports: "import { parseRole, safeRedirectPath, type Role } from '@payload-auth-link/core'",
    body: [
      "const role: Role = parseRole('admin')._unsafeUnwrap()",
      "const destination: string = safeRedirectPath('/account')",
    ],
  },
  web: {
    imports: "import { createSessionVerifier, requireRoles } from '@payload-auth-link/web'",
    body: [
      "const verify = createSessionVerifier({ baseUrl: 'https://example.com' })",
      'export const guard = (headers: Headers) =>',
      "  requireRoles(headers, verify, { roles: [parseRole('admin')._unsafeUnwrap()] })",
    ],
  },
  plugin: {
    imports: "import { authLink } from '@payload-auth-link/plugin'",
    body: [],
  },
  next: {
    imports: "import { createAuthMiddleware } from '@payload-auth-link/next'",
    body: ["export const middleware = createAuthMiddleware({ sessionCookieNames: ['a'] })"],
  },
  'tanstack-start': {
    imports: "import { createAuthRequestMiddleware } from '@payload-auth-link/tanstack-start'",
    body: [
      'export const startMiddleware =',
      "  createAuthRequestMiddleware({ sessionCookieNames: ['a'] })",
    ],
  },
  react: {
    imports: "import { AuthLinkProvider } from '@payload-auth-link/react'",
    body: [],
  },
  'provider-better-auth': {
    imports: "import { createBetterAuthEngine } from '@payload-auth-link/provider-better-auth'",
    body: [],
  },
  'provider-authjs': {
    imports: "import { createAuthJsEngine } from '@payload-auth-link/provider-authjs'",
    body: [],
  },
}
// cross-package wiring keeps at least one multi-package line honest
// when core+web are both present.
const hasCore = typeNames.includes('core')
const consumerLines = typeNames.flatMap((name) => {
  const snippet = consumerSnippets[name]
  if (snippet === undefined) {
    throw new Error(`verify-published: no consumer snippet for ${name}`)
  }
  return [snippet.imports, ...snippet.body]
})
if (hasCore && !names.includes('web')) {
  consumerLines.push(`export const stillTyped: string = safeRedirectPath('/account')`)
}
writeFileSync(join(consumer, 'consumer.ts'), `${consumerLines.join('\n')}\n`)
run('npx', ['tsc', '-p', 'tsconfig.json'])

const local = JSON.parse(readFileSync(join(root, 'packages', 'core', 'package.json'), 'utf8'))
process.stdout.write(
  `\nverified @payload-auth-link/*@${version} from the public registry` +
    `${expectProvenance ? ' with provenance' : ''} (repo is at ${local.version})\n`
)
