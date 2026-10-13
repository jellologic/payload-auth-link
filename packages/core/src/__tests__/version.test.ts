import { describe, expect, it } from 'vitest'
import { UnsupportedVersionError } from '../errors.js'
import {
  assertSupportedVersion,
  describeBand,
  isSupportedVersion,
  parseVersion,
  readInstalledVersion,
  type VersionRange,
} from '../version.js'

const payloadBand: readonly VersionRange[] = [
  { min: '3.83.0', maxExclusive: '4.0.0' },
  { exact: '4.0.0-beta.0' },
]
const baBand: readonly VersionRange[] = [{ min: '1.7.6', maxExclusive: '1.8.0' }]

describe('parseVersion', () => {
  it('parses releases, prereleases, and build metadata', () => {
    expect(parseVersion('1.7.6')).toEqual({ major: 1, minor: 7, patch: 6, prerelease: null })
    expect(parseVersion('4.0.0-beta.0')).toEqual({
      major: 4,
      minor: 0,
      patch: 0,
      prerelease: 'beta.0',
    })
    expect(parseVersion('3.90.2+build.5')).toEqual({
      major: 3,
      minor: 90,
      patch: 2,
      prerelease: null,
    })
    expect(parseVersion('v1.2.3')).toBeNull()
    expect(parseVersion('1.2')).toBeNull()
    expect(parseVersion('latest')).toBeNull()
    expect(parseVersion('')).toBeNull()
  })
})

describe('isSupportedVersion', () => {
  it('accepts inside, rejects outside the bisected bands', () => {
    expect(isSupportedVersion('1.7.6', baBand)).toBe(true)
    expect(isSupportedVersion('1.7.7', baBand)).toBe(true)
    expect(isSupportedVersion('1.7.5', baBand)).toBe(false)
    expect(isSupportedVersion('1.8.0', baBand)).toBe(false)
    expect(isSupportedVersion('2.0.0', baBand)).toBe(false)
    expect(isSupportedVersion('3.83.0', payloadBand)).toBe(true)
    expect(isSupportedVersion('3.82.0', payloadBand)).toBe(false)
    expect(isSupportedVersion('3.90.2', payloadBand)).toBe(true)
    expect(isSupportedVersion('4.0.0', payloadBand)).toBe(false)
  })

  it('never admits prereleases through a range (the B10 canary leak)', () => {
    expect(isSupportedVersion('4.0.0-beta.0', payloadBand)).toBe(true)
    expect(isSupportedVersion('4.0.0-canary.39', payloadBand)).toBe(false)
    expect(isSupportedVersion('3.90.2-beta.1', payloadBand)).toBe(false)
    expect(isSupportedVersion('1.7.8-rc.1', baBand)).toBe(false)
  })
})

describe('assertSupportedVersion', () => {
  it('throws a typed, actionable error outside the band', () => {
    expect(() => assertSupportedVersion('better-auth', '1.6.33', baBand)).toThrow(
      UnsupportedVersionError
    )
    try {
      assertSupportedVersion('better-auth', '1.6.33', baBand)
    } catch (error) {
      expect(error).toMatchObject({
        code: 'UNSUPPORTED_VERSION',
        packageName: 'better-auth',
        found: '1.6.33',
        supported: '>=1.7.6 <1.8.0',
      })
    }
    expect(() => assertSupportedVersion('better-auth', '1.7.7', baBand)).not.toThrow()
    expect(describeBand(payloadBand)).toBe('>=3.83.0 <4.0.0 || 4.0.0-beta.0')
  })
})

describe('readInstalledVersion', () => {
  it('reads the caller-visible manifest, even behind a closed exports map', () => {
    // zod resolves from core's own deps; `@auth/core` famously blocks
    // the `./package.json` subpath, so the walk-up path matters.
    expect(readInstalledVersion('zod')).toMatch(/^\d+\.\d+\.\d+/)
  })

  it('returns null for packages the caller cannot see or that do not exist', () => {
    expect(readInstalledVersion('definitely-not-a-real-package-42')).toBeNull()
  })
})
