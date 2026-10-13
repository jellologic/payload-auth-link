/**
 * Generated-docs freshness gate (CI `docs-fresh` job).
 *
 * - `llms.txt` / `llms-full.txt`: regenerating must be a no-op. A drift
 *   means a docs edit landed without `bun run docs:llms`.
 * - `docs/media`: every referenced screenshot exists and every file in
 *   the folder is referenced (regenerate with `bun run docs:media`).
 *
 * `docs/api` is gitignored, so its freshness gate is a strict typedoc
 * build (`typedoc --treatWarningsAsErrors`), run beside this script.
 *
 * Run: `bun run docs:check`.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

const generated = ['llms.txt', 'llms-full.txt']
const before = new Map(generated.map((path) => [path, readFileSync(join(root, path), 'utf8')]))
execFileSync(process.execPath, [join(root, 'scripts', 'build-llms.mjs')], { stdio: 'inherit' })
for (const path of generated) {
  if (readFileSync(join(root, path), 'utf8') !== before.get(path)) {
    failures.push(`${path} is stale: run \`bun run docs:llms\` and commit the result`)
  }
}

const markdown = [
  'README.md',
  ...readdirSync(join(root, 'docs'))
    .filter((name) => name.endsWith('.md'))
    .map((name) => join('docs', name)),
]
const referenced = new Set()
for (const path of markdown) {
  for (const match of readFileSync(join(root, path), 'utf8').matchAll(
    /media\/([A-Za-z0-9._-]+\.(?:png|jpe?g|gif|webp|svg))/g
  )) {
    referenced.add(match[1])
  }
}
const mediaDir = join(root, 'docs', 'media')
const present = new Set(existsSync(mediaDir) ? readdirSync(mediaDir) : [])
for (const name of referenced) {
  if (!present.has(name)) {
    failures.push(`docs/media/${name} is referenced but missing: run \`bun run docs:media\``)
  }
}
for (const name of present) {
  if (!referenced.has(name)) {
    failures.push(`docs/media/${name} is not referenced by any doc: delete or link it`)
  }
}

// Peer-range drift (issue #19): the README sentence is generated
// from package.json — any hand edit fails here.
for (const name of readdirSync(join(root, 'packages'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()) {
  const manifest = JSON.parse(readFileSync(join(root, 'packages', name, 'package.json'), 'utf8'))
  const peers = manifest.peerDependencies ?? {}
  const readmePath = join(root, 'packages', name, 'README.md')
  if (!existsSync(readmePath) || Object.keys(peers).length === 0) {
    continue
  }
  const readme = readFileSync(readmePath, 'utf8')
  // Prose may phrase the sentence its own way, but every manifest
  // range must appear verbatim next to its package name — stale
  // ranges are exactly the drift this catches.
  for (const [peer, range] of Object.entries(peers)) {
    if (!readme.includes(`\`${peer}\``) || !readme.includes(String(range))) {
      failures.push(
        `packages/${name}/README.md does not state peer \`${peer}\` ${range} as package.json declares`
      )
    }
  }
}

if (failures.length > 0) {
  process.stderr.write(
    `docs freshness check failed:\n${failures.map((f) => `- ${f}`).join('\n')}\n`
  )
  process.exit(1)
}
process.stdout.write('docs fresh: llms artifacts idempotent, media references complete\n')
