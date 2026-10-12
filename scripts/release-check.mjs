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
    const walk = (current) => {
      for (const entry of readdirSync(current, { withFileTypes: true })) {
        const path = join(current, entry.name)
        if (entry.isDirectory()) {
          walk(path)
          continue
        }
        files.push(path.slice(shipped.length + 1))
        if (!entry.name.endsWith('.js')) {
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
          imports.add(specifier.startsWith('@') ? parts.slice(0, 2).join('/') : (parts[0] ?? ''))
        }
      }
    }
    walk(shipped)
    return {
      leaksWorkspace: manifestText.includes('workspace:'),
      // Undeclared imports install fine here (hoisting) and crash for
      // real consumers with ERR_MODULE_NOT_FOUND.
      undeclared: [...imports].filter((name) => !declared.has(name)).sort(),
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
  if (packed.testFiles.length > 0) {
    console.error(
      `release:check failed: ${name} ships ${packed.testFiles.length} test/fixture files`
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
