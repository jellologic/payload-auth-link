/**
 * Publish every package whose current version is not on npm yet.
 *
 * Why not `changeset publish`: it shells out to plain `npm publish`,
 * which ships `workspace:*` dependency ranges verbatim (uninstallable).
 * `bun pm pack` rewrites them to the real versions, so each package is
 * packed with Bun and the tarball is published with npm. npm keeps
 * trusted publishing (OIDC) and provenance in CI. Locally — only the
 * very first publish, before a trusted publisher can be attached —
 * provenance is off (it requires a CI identity).
 *
 * Tags: for every published version whose `<name>@<version>` tag is
 * missing on origin (just published, or published by an earlier run that
 * died before tagging), the script creates the local tag and appends a
 * `{"type":"git-tag",…}` event to `$CHANGESETS_OUTPUT`. That file is
 * changesets/action's contract: it pushes those tags and creates the
 * GitHub releases. (The CLI's deprecated `changeset tag` no longer
 * writes it, so the script owns the contract.)
 *
 * Run: `bun run release` (CI) · `bun scripts/publish.mjs --dry-run`.
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gitTagEvent } from './changesets-output.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dryRun = process.argv.includes('--dry-run')
const inCi = process.env.GITHUB_ACTIONS === 'true'

// Dependencies first, so a partial failure never leaves a published
// package pointing at an unpublished sibling version.
const order = [
  'core',
  'web',
  'react',
  'plugin',
  'next',
  'tanstack-start',
  'provider-better-auth',
  'provider-authjs',
]
const present = readdirSync(join(root, 'packages'))
const missing = present.filter((name) => !order.includes(name))
if (missing.length > 0) {
  throw new Error(`publish order is missing packages: ${missing.join(', ')}`)
}

function isPublished(name, version) {
  try {
    const out = execFileSync('npm', ['view', `${name}@${version}`, 'version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return out.trim() === version
  } catch {
    return false
  }
}

function tagOnOrigin(tag) {
  const out = execFileSync('git', ['ls-remote', '--tags', 'origin', `refs/tags/${tag}`], {
    cwd: root,
    encoding: 'utf8',
  })
  return out.trim() !== ''
}

const work = mkdtempSync(join(tmpdir(), 'pal-publish-'))
let published = 0
const live = []
try {
  for (const name of order) {
    const dir = join(root, 'packages', name)
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
    if (manifest.private === true) {
      continue
    }
    const id = `${manifest.name}@${manifest.version}`
    if (isPublished(manifest.name, manifest.version)) {
      process.stdout.write(`skip ${id} (already on npm)\n`)
      live.push(manifest)
      continue
    }
    const dest = join(work, name)
    execFileSync('bun', ['pm', 'pack', '--destination', dest], { cwd: dir, stdio: 'inherit' })
    const tarball = readdirSync(dest).find((file) => file.endsWith('.tgz'))
    if (tarball === undefined) {
      throw new Error(`bun pm pack produced no tarball for ${id}`)
    }
    const packed = execFileSync('tar', ['-xzOf', join(dest, tarball), 'package/package.json'], {
      encoding: 'utf8',
    })
    if (packed.includes('workspace:')) {
      throw new Error(`${id}: packed manifest still contains a workspace: range`)
    }
    const args = ['publish', join(dest, tarball), '--access', 'public']
    args.push(inCi ? '--provenance' : '--provenance=false')
    if (dryRun) {
      args.push('--dry-run')
    }
    execFileSync('npm', args, { stdio: 'inherit' })
    published += 1
    live.push(manifest)
    process.stdout.write(`${dryRun ? 'would publish' : 'published'} ${id}\n`)
  }
} finally {
  rmSync(work, { recursive: true, force: true })
}

if (!dryRun) {
  const outputPath = process.env.CHANGESETS_OUTPUT
  for (const manifest of live) {
    const tag = `${manifest.name}@${manifest.version}`
    if (tagOnOrigin(tag)) {
      continue
    }
    try {
      execFileSync('git', ['tag', tag], { cwd: root, stdio: 'ignore' })
    } catch {
      // Already exists locally (an earlier interrupted run): reuse it.
    }
    if (outputPath !== undefined && outputPath !== '') {
      appendFileSync(outputPath, gitTagEvent(manifest.name, manifest.version))
    }
    process.stdout.write(`New tag: ${tag}\n`)
  }
}
process.stdout.write(`${published} package(s) ${dryRun ? 'checked' : 'published'}\n`)
