/**
 * Pre-publish packaging gate: `publint` + `are-the-types-wrong` over
 * every publishable package. All packages are ESM-only by decision
 * (`type: module`, engines node>=20.9, bundler/nodenext resolution),
 * so attw runs under the `esm-only` profile — legacy node10/CJS
 * resolution failures are the documented tradeoff, not a bug.
 *
 * Run: `bun run release:check` (after `bun run build`).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { builtinModules } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const packages = readdirSync(join(root, 'packages'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()

// Does `name` (resolved from the package directory) ship its own
// declarations, or does the manifest depend on `@types/<name>`?
function hasTypes(dir, name, manifest) {
  const typesName = `@types/${name.startsWith('@') ? name.slice(1).replace('/', '__') : name}`
  if (typesName in (manifest.dependencies ?? {})) {
    return true
  }
  let current = dir
  for (;;) {
    const candidate = join(current, 'node_modules', name, 'package.json')
    if (existsSync(candidate)) {
      const dep = JSON.parse(readFileSync(candidate, 'utf8'))
      return (
        typeof dep.types === 'string' ||
        typeof dep.typings === 'string' ||
        JSON.stringify(dep.exports ?? {}).includes('"types"') ||
        existsSync(join(dirname(candidate), 'index.d.ts'))
      )
    }
    const parent = dirname(current)
    if (parent === current) {
      return false
    }
    current = parent
  }
}

// Inspect exactly what consumers get: pack the way `scripts/publish.mjs`
// publishes (bun rewrites `workspace:*` to real versions), extract, and
// check the shipped files — not the local build output.
function inspectPacked(dir) {
  const dest = mkdtempSync(join(tmpdir(), 'pal-release-check-'))
  try {
    execFileSync('bun', ['pm', 'pack', '--destination', dest, '--quiet'], { cwd: dir })
    const tarball = readdirSync(dest).find((file) => file.endsWith('.tgz'))
    if (tarball === undefined) {
      throw new Error('bun pm pack produced no tarball')
    }
    execFileSync('tar', ['-xzf', join(dest, tarball), '-C', dest])
    const shipped = join(dest, 'package')
    const manifestText = readFileSync(join(shipped, 'package.json'), 'utf8')
    const manifest = JSON.parse(manifestText)
    const declared = new Set([
      manifest.name,
      ...Object.keys(manifest.dependencies ?? {}),
      ...Object.keys(manifest.peerDependencies ?? {}),
    ])
    const files = []
    const imports = new Set()
    const typeImports = new Set()
    const walk = (current) => {
      for (const entry of readdirSync(current, { withFileTypes: true })) {
        const path = join(current, entry.name)
        if (entry.isDirectory()) {
          walk(path)
          continue
        }
        files.push(path.slice(shipped.length + 1))
        const target = entry.name.endsWith('.d.ts')
          ? typeImports
          : entry.name.endsWith('.js')
            ? imports
            : null
        if (target === null) {
          continue
        }
        // Strip comments first: TSDoc examples survive compilation and
        // would read as imports.
        const source = readFileSync(path, 'utf8')
          .replace(/\/\*[\s\S]*?\*\//g, '')
          .replace(/^\s*\/\/.*$/gm, '')
        for (const match of source.matchAll(/(?:from|import\()\s*['"]([^'"./][^'"]*)['"]/g)) {
          const specifier = match[1] ?? ''
          if (specifier.startsWith('node:') || builtinModules.includes(specifier)) {
            continue
          }
          const parts = specifier.split('/')
          target.add(specifier.startsWith('@') ? parts.slice(0, 2).join('/') : (parts[0] ?? ''))
        }
      }
    }
    walk(shipped)
    return {
      leaksWorkspace: manifestText.includes('workspace:'),
      // Undeclared imports install fine here (hoisting) and crash for
      // real consumers with ERR_MODULE_NOT_FOUND.
      undeclared: [...imports, ...typeImports].filter((name) => !declared.has(name)).sort(),
      // A shipped .d.ts importing a package that has no types of its
      // own (and no @types/* dependency) is TS7016 for every consumer
      // compiling with skipLibCheck off (issue #85: `pg`). Peers are
      // excluded: their types (e.g. @types/react) are the consumer's
      // install, like the peer itself.
      untyped: [...typeImports]
        .filter((name) => name in (manifest.dependencies ?? {}))
        .filter((name) => !hasTypes(dir, name, manifest))
        .sort(),
      // MIT requires the notice to travel with every copy.
      license: files.includes('LICENSE'),
      testFiles: files.filter((file) => /(^|\/)__(tests|fixtures)__\//.test(file)),
    }
  } finally {
    rmSync(dest, { recursive: true, force: true })
  }
}

let failed = false
for (const name of packages) {
  const dir = join(root, 'packages', name)
  const packed = inspectPacked(dir)
  if (packed.undeclared.length > 0) {
    console.error(
      `release:check failed: ${name} ships imports of undeclared packages: ${packed.undeclared.join(', ')}`
    )
    failed = true
  }
  if (packed.untyped.length > 0) {
    console.error(
      `release:check failed: ${name} ships .d.ts imports of packages without types (add @types/* to dependencies or stop exposing them): ${packed.untyped.join(', ')}`
    )
    failed = true
  }
  // Each package commits a copy of the root LICENSE (`files` would
  // otherwise leave it out of the tarball); copies must not drift.
  if (!packed.license) {
    console.error(`release:check failed: ${name} tarball has no LICENSE`)
    failed = true
  }
  const licensePath = join(dir, 'LICENSE')
  if (
    !existsSync(licensePath) ||
    readFileSync(licensePath, 'utf8') !== readFileSync(join(root, 'LICENSE'), 'utf8')
  ) {
    console.error(`release:check failed: packages/${name}/LICENSE must equal the root LICENSE`)
    failed = true
  }
  if (packed.testFiles.length > 0) {
    console.error(
      `release:check failed: ${name} ships ${packed.testFiles.length} test/fixture files`
    )
    failed = true
  }
  // npm verifies provenance against `repository`: a missing or
  // mismatched URL makes the trusted CI publish fail with E422.
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
  const repository = manifest.repository ?? {}
  if (
    repository.url !== 'git+https://github.com/jellologic/payload-auth-link.git' ||
    repository.directory !== `packages/${name}`
  ) {
    console.error(
      `release:check failed: ${name} repository must point at this repo and packages/${name}`
    )
    failed = true
  }
  // The README is the npm landing page: never publish without one.
  if (!existsSync(join(dir, 'README.md'))) {
    console.error(`release:check failed: ${name} has no README.md (its npm page would be empty)`)
    failed = true
  }
  if (packed.leaksWorkspace) {
    console.error(`release:check failed: ${name} packs a workspace: dependency range`)
    failed = true
  }
  for (const [tool, args] of [
    ['publint', [dir]],
    ['attw', ['--pack', '--profile', 'esm-only', dir]],
  ]) {
    try {
      execFileSync('bunx', [tool, ...args], { stdio: 'inherit', cwd: root })
    } catch {
      console.error(`release:check failed: ${tool} ${name}`)
      failed = true
    }
  }
}
if (failed) {
  process.exit(1)
}
console.log(`release:check passed for ${packages.join(', ')}`)
