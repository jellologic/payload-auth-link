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
import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const packages = readdirSync(join(root, 'packages'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()

// Pack the way `scripts/publish.mjs` publishes (bun rewrites
// `workspace:*` to real versions) and fail if any range survived:
// a published `workspace:` dependency is uninstallable.
function packedManifest(dir) {
  const dest = mkdtempSync(join(tmpdir(), 'pal-release-check-'))
  try {
    execFileSync('bun', ['pm', 'pack', '--destination', dest, '--quiet'], { cwd: dir })
    const tarball = readdirSync(dest).find((file) => file.endsWith('.tgz'))
    if (tarball === undefined) {
      throw new Error('bun pm pack produced no tarball')
    }
    return execFileSync('tar', ['-xzOf', join(dest, tarball), 'package/package.json'], {
      encoding: 'utf8',
    })
  } finally {
    rmSync(dest, { recursive: true, force: true })
  }
}

let failed = false
for (const name of packages) {
  const dir = join(root, 'packages', name)
  if (packedManifest(dir).includes('workspace:')) {
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
