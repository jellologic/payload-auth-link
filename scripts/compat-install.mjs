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
 *   next                   next
 *
 * Only exact versions are rewritten (never ranges, never
 * `workspace:*`), so peers keep their declared bands — the point of
 * a floor cell is to install the floor while the ranges stay honest.
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const [axis, version] = process.argv.slice(2)

const axes = {
  payload: [/^payload$/, /^@payloadcms\//],
  'better-auth': [/^better-auth$/, /^@better-auth\//],
  '@auth/core': [/^@auth\/core$/],
  '@tanstack/react-start': [/^@tanstack\/react-start$/],
  next: [/^next$/],
}

/** Upstreams with no publish at some floor versions (e.g. the v4-line
 * `@payloadcms/tanstack-start` predates payload 3.83): leave their pin
 * alone — floor cells test `packages/*`, not the examples. */
const axisExclusions = {
  payload: ['@payloadcms/tanstack-start'],
}

const patterns = axes[axis]
if (patterns === undefined || version === undefined) {
  console.error(`usage: compat-install.mjs <${Object.keys(axes).join('|')}> <exact-version>`)
  process.exit(2)
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
console.log(
  `compat-install: ${touched} pinned entr${touched === 1 ? 'y' : 'ies'} moved to ${axis}@${version}`
)
