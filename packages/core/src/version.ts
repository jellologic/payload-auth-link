import { existsSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { UnsupportedVersionError } from './errors.js'
import { isNonEmptyString, isRecord } from './guards.js'

/**
 * One supported upstream version range. A band is a list of these:
 * version lines we have actually validated (bisected floor, tested
 * ceiling), never a hopeful caret. Prerelease versions match only
 * via an `exact` entry — the B10 canary leak came from semver
 * prerelease ordering silently admitting untested builds.
 */
export type VersionRange =
  { readonly min: string; readonly maxExclusive: string } | { readonly exact: string }

/** Parsed semver core; `prerelease` is `null` for plain releases. */
export type ParsedVersion = {
  readonly major: number
  readonly minor: number
  readonly patch: number
  readonly prerelease: string | null
}

const versionPattern = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

/** Parse `major.minor.patch[-prerelease][+build]`; `null` if unparsable. */
export function parseVersion(version: string): ParsedVersion | null {
  const match = versionPattern.exec(version.trim())
  if (match === null) {
    return null
  }
  const [, major, minor, patch, prerelease] = match
  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    prerelease: prerelease ?? null,
  }
}

function compareCore(a: ParsedVersion, b: ParsedVersion): number {
  for (const key of ['major', 'minor', 'patch'] as const) {
    if (a[key] !== b[key]) {
      return a[key] - b[key]
    }
  }
  return 0
}

/** True when `version` falls inside any range of the band. */
export function isSupportedVersion(version: string, band: readonly VersionRange[]): boolean {
  const parsed = parseVersion(version)
  if (parsed === null) {
    return false
  }
  for (const range of band) {
    if ('exact' in range) {
      if (version.trim() === range.exact) {
        return true
      }
      continue
    }
    if (parsed.prerelease !== null) {
      continue
    }
    const min = parseVersion(range.min)
    const max = parseVersion(range.maxExclusive)
    if (min === null || max === null) {
      continue
    }
    if (compareCore(parsed, min) >= 0 && compareCore(parsed, max) < 0) {
      return true
    }
  }
  return false
}

/** Human-readable band, for error messages (`>=1.7.6 <1.8.0 || 4.0.0-beta.0`). */
export function describeBand(band: readonly VersionRange[]): string {
  return band
    .map((range) => ('exact' in range ? range.exact : `>=${range.min} <${range.maxExclusive}`))
    .join(' || ')
}

/**
 * Startup version assertion (upgrade resilience Phase 1): an
 * upstream version outside the validated band fails at wiring time
 * with {@link UnsupportedVersionError} — before any collection
 * write — instead of surfacing later as a raw SQL error, a missing
 * adapter method, or a silently wrong schema.
 */
export function assertSupportedVersion(
  packageName: string,
  installedVersion: string,
  band: readonly VersionRange[]
): void {
  if (!isSupportedVersion(installedVersion, band)) {
    throw new UnsupportedVersionError(packageName, installedVersion, describeBand(band))
  }
}

/**
 * Read the installed version of an upstream package from its
 * `package.json` manifest. Resolution follows the caller: pass the
 * importing module's `import.meta.url` as `fromUrl` so the manifest
 * resolves through the caller's own dependency tree (under strict
 * linkers, core cannot see the caller's deps). The manifest is
 * located by resolving the package entry and walking up — some
 * packages (`@auth/core`) block the `./package.json` subpath in
 * their `exports`. Returns `null` when nothing resolves (exotic
 * bundling) — callers decide whether that skips the assertion (with
 * a warning) or fails.
 */
export function readInstalledVersion(packageName: string, fromUrl?: string): string | null {
  try {
    const require = createRequire(fromUrl ?? import.meta.url)
    let dir = dirname(require.resolve(packageName))
    for (let depth = 0; depth < 6; depth += 1) {
      const manifestPath = join(dir, 'package.json')
      if (existsSync(manifestPath)) {
        const manifest: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'))
        return isRecord(manifest) && isNonEmptyString(manifest.version) ? manifest.version : null
      }
      const parent = dirname(dir)
      if (parent === dir) {
        return null
      }
      dir = parent
    }
    return null
  } catch {
    return null
  }
}
