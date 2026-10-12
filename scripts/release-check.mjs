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
import { readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const packages = readdirSync(join(root, 'packages'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()

let failed = false
for (const name of packages) {
  const dir = join(root, 'packages', name)
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
