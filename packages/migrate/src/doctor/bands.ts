import {
  describeBand,
  isSupportedVersion,
  readInstalledVersion,
  type VersionRange,
} from '@payload-auth-link/core'
import type { VersionFinding } from './types.js'

/**
 * The bands the doctor checks against. These mirror the authoritative
 * constants — `supportedPayloadBand` (packages/plugin) and
 * `supportedBetterAuthBand` (packages/provider-better-auth) — and a
 * unit test asserts the copies never drift from them, so the doctor
 * cannot promise a band the runtime would refuse.
 */
export const payloadBand: readonly VersionRange[] = [
  { min: '3.83.0', maxExclusive: '4.0.0' },
  { exact: '4.0.0-beta.0' },
]
export const betterAuthBand: readonly VersionRange[] = [{ min: '1.7.6', maxExclusive: '1.8.0' }]
/** Next is a peer of the Next adapter; the doctor reports it informationally. */
export const nextBand: readonly VersionRange[] = [{ min: '15.0.0', maxExclusive: '17.0.0' }]

/**
 * Better Auth minors this doctor knows the payload-auth app must move
 * off: 1.6 removed `oidcProvider` in 1.7 and payload-auth's peer range
 * still admits 1.4+, so an app can sit far below the supported band
 * without anything telling it.
 */
function versionFinding(
  name: string,
  band: readonly VersionRange[],
  fromUrl: string,
  note?: (installed: string | null) => string | undefined
): VersionFinding {
  const installed = readInstalledVersion(name, fromUrl)
  const status =
    installed === null ? 'unknown' : isSupportedVersion(installed, band) ? 'ok' : 'blocker'
  const base =
    installed === null
      ? 'could not read the installed manifest; resolve the version manually'
      : isSupportedVersion(installed, band)
        ? `installed ${installed} is inside the supported band`
        : `installed ${installed} is OUTSIDE the supported band; upgrade before migrating`
  return {
    name,
    installed,
    band: describeBand(band),
    status,
    detail: [base, note?.(installed)].filter((part) => part !== undefined).join(' — '),
  }
}

/** Band checks for the three upstreams that gate a migration. */
export function checkVersions(fromUrl: string): VersionFinding[] {
  return [
    versionFinding('payload', payloadBand, fromUrl),
    versionFinding('better-auth', betterAuthBand, fromUrl, (installed) =>
      installed !== null &&
      (installed.startsWith('1.4.') || installed.startsWith('1.5.') || installed.startsWith('1.6.'))
        ? 'better-auth 1.7 removed `oidcProvider` and the `mcp` plugin; an OAuth 2.1 server moves to @better-auth/oauth-provider (a schema migration — see the journey notes in issue #60)'
        : undefined
    ),
    versionFinding('next', nextBand, fromUrl),
  ]
}
