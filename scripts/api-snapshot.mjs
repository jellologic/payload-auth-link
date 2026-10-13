/**
 * Public-API type snapshot gate (PLAN-UPGRADE-RESILIENCE Phase 3b,
 * B18). Concatenates every shipped `.d.ts` per package into
 * `snapshots/api/<pkg>.txt`. `--check` (wired into `bun run check`)
 * fails when the built surface differs from the committed snapshot:
 * a breaking type change can no longer ship as a silent patch.
 *
 * When this fails on purpose: review the diff for semver impact,
 * add a changeset at the right bump level, then regenerate with
 * `bun run api:snapshot` and commit the new snapshot.
 *
 * Run after `bun run build`.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const snapshotDir = join(root, 'snapshots', 'api')
const mode = process.argv[2]

if (mode !== '--check' && mode !== '--write') {
  console.error('usage: api-snapshot.mjs --check|--write')
  process.exit(2)
}

function declarationFiles(dir) {
  const files = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name !== '__tests__' && entry.name !== '__fixtures__') {
        files.push(...declarationFiles(path))
      }
    } else if (entry.name.endsWith('.d.ts')) {
      files.push(path)
    }
  }
  return files.sort()
}

const packages = readdirSync(join(root, 'packages'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()

let failed = false
mkdirSync(snapshotDir, { recursive: true })

for (const pkg of packages) {
  const dist = join(root, 'packages', pkg, 'dist')
  if (!existsSync(dist)) {
    console.error(`api-snapshot: packages/${pkg}/dist missing — run bun run build first`)
    process.exit(2)
  }
  const parts = declarationFiles(dist).map((file) => {
    const rel = relative(dist, file)
    const text = readFileSync(file, 'utf8')
      .replace(/^\/\/# sourceMappingURL=.*$/m, '')
      .trimEnd()
    return `// ===== ${rel} =====\n${text}\n`
  })
  const snapshot = parts.join('\n')
  const target = join(snapshotDir, `${pkg}.txt`)
  if (mode === '--write') {
    writeFileSync(target, snapshot)
    console.log(`api-snapshot: wrote snapshots/api/${pkg}.txt`)
  } else if (!existsSync(target) || readFileSync(target, 'utf8') !== snapshot) {
    failed = true
    console.error(
      `api-snapshot: public API of packages/${pkg} differs from snapshots/api/${pkg}.txt.\n` +
        'Review the type-surface diff for semver impact, add a changeset, ' +
        'then run: bun run api:snapshot'
    )
  }
}

if (failed) {
  process.exit(1)
}
if (mode === '--check') {
  console.log('api-snapshot: all package type surfaces match their snapshots')
}
