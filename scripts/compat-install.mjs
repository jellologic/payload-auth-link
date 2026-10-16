/**
 * Compatibility-matrix helper (PLAN-UPGRADE-RESILIENCE Phase 1):
 * `bun scripts/compat-install.mjs <axis> <version>` rewrites every
 * pinned (exact) manifest entry on the axis across the workspace,
 * then the caller runs `bun install`. Used by .github/workflows/
 * compat.yml to prove {floor, latest} cells, and locally to bisect.
 *
 * Axes:
 *   payload                payload + @payloadcms/* (shipped deps)
 *   better-auth            better-auth + @better-auth/*
 *   @auth/core             @auth/core
 *   @tanstack/react-start  @tanstack/react-start
 *   @tanstack/react-router @tanstack/react-router
 *   next                   next
 *
 * `<version>` is an exact version, or `latest:<semver range>`: the
 * newest stable (non-prerelease) publish of the axis package inside
 * that range. Latest cells pass the supported band as the range, so
 * "latest" means latest-in-band — never a dist-tag that has already
 * moved past the band (payload 4 GA, better-auth 1.8, next 17).
 *
 * Only exact versions are rewritten (never ranges, never
 * `workspace:*`), so peers keep their declared bands — the point of
 * a floor cell is to install the floor while the ranges stay honest.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const [axis, requested] = process.argv.slice(2)

const axes = {
  payload: [/^payload$/, /^@payloadcms\//],
  'better-auth': [/^better-auth$/, /^@better-auth\//],
  '@auth/core': [/^@auth\/core$/],
  '@tanstack/react-start': [/^@tanstack\/react-start$/],
  '@tanstack/react-router': [/^@tanstack\/react-router$/],
  next: [/^next$/],
}

/** Order two stable `x.y.z` versions numerically. */
function compareStable(a, b) {
  const left = a.split('.').map(Number)
  const right = b.split('.').map(Number)
  for (let index = 0; index < 3; index += 1) {
    const delta = (left[index] ?? 0) - (right[index] ?? 0)
    if (delta !== 0) {
      return delta
    }
  }
  return 0
}

/** Newest stable publish of `name` inside `range` (npm resolves the range). */
function resolveLatestInRange(name, range) {
  const raw = execFileSync('npm', ['view', `${name}@${range}`, 'version', '--json'], {
    encoding: 'utf8',
  }).trim()
  if (raw === '') {
    return undefined
  }
  const parsed = JSON.parse(raw)
  const versions = (Array.isArray(parsed) ? parsed : [parsed]).filter(
    (candidate) => typeof candidate === 'string' && !candidate.includes('-')
  )
  versions.sort(compareStable)
  return versions.at(-1)
}

/** Upstreams with no publish at some floor versions (e.g. the v4-line
 * `@payloadcms/tanstack-start` predates payload 3.83): leave their pin
 * alone — floor cells test `packages/*`, not the examples. */
const axisExclusions = {
  payload: ['@payloadcms/tanstack-start'],
}

const patterns = axes[axis]
if (patterns === undefined || requested === undefined) {
  console.error(
    `usage: compat-install.mjs <${Object.keys(axes).join('|')}> <exact-version|latest:<range>>`
  )
  process.exit(2)
}

let version = requested
if (requested.startsWith('latest:')) {
  const range = requested.slice('latest:'.length)
  const resolved = resolveLatestInRange(axis, range)
  if (resolved === undefined) {
    console.error(`compat-install: no stable ${axis} publish satisfies ${range}`)
    process.exit(1)
  }
  console.log(`compat-install: ${axis} latest in ${range} is ${resolved}`)
  version = resolved
}

const manifestPaths = [join(root, 'package.json')]
for (const dir of ['packages', 'examples']) {
  let names
  try {
    names = readdirSync(join(root, dir), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
  } catch {
    continue
  }
  for (const name of names) {
    manifestPaths.push(join(root, dir, name, 'package.json'))
  }
}

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies']
let touched = 0
for (const path of manifestPaths) {
  let manifest
  try {
    manifest = JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    continue
  }
  let changed = false
  for (const section of SECTIONS) {
    const deps = manifest[section]
    if (deps === undefined) {
      continue
    }
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== 'string' || !patterns.some((pattern) => pattern.test(name))) {
        continue
      }
      if ((axisExclusions[axis] ?? []).includes(name)) {
        continue
      }
      // Exact pins only: floors replace pins; ranges stay honest.
      if (/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(spec) && spec !== version) {
        deps[name] = version
        changed = true
        touched += 1
        continue
      }
      // BA satellites peer-lock to exact BA minors, so a caret devDep
      // (`@better-auth/passkey: ^1.7.7`) refuses a floor install of
      // better-auth 1.7.6. Pin same-major satellite carets to the
      // cell's exact version; other ranges stay honest.
      if (
        axis === 'better-auth' &&
        name.startsWith('@better-auth/') &&
        /^\^\d+\.\d+\.\d+/.test(spec) &&
        spec.slice(1).split('.')[0] === version.split('.')[0]
      ) {
        deps[name] = version
        changed = true
        touched += 1
      }
    }
  }
  if (changed) {
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`)
    console.log(`compat-install: ${axis}@${version} -> ${join(...path.split('/').slice(-3))}`)
  }
}
// Satellites (`@better-auth/api-key`, `/passkey`) depend on
// `@better-auth/core` by range, which resolves to the newest core: a
// floor cell then type-checks against two cores. Pin it to the cell.
if (axis === 'better-auth') {
  const rootPath = join(root, 'package.json')
  const rootManifest = JSON.parse(readFileSync(rootPath, 'utf8'))
  rootManifest.overrides = { ...rootManifest.overrides, '@better-auth/core': version }
  writeFileSync(rootPath, `${JSON.stringify(rootManifest, null, 2)}\n`)
  console.log(`compat-install: overrides @better-auth/core -> ${version}`)
}
console.log(
  `compat-install: ${touched} pinned entr${touched === 1 ? 'y' : 'ies'} moved to ${axis}@${version}`
)
