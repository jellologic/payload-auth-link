import { describe, expect, test } from 'vitest'
import {
  betterAuthBand as doctorBaBand,
  payloadBand as doctorPayloadBand,
} from '../doctor/bands.js'

/**
 * The doctor's band copies must never promise more than the runtime
 * asserts — a migrating app that passes the doctor but fails the
 * plugin's wiring assertion would be a doctor bug.
 */
describe('doctor bands mirror the runtime assertions', () => {
  test('payload band matches supportedPayloadBand', { timeout: 120_000 }, async () => {
    const plugin = await import('@payload-auth-link/plugin')
    expect(doctorPayloadBand).toEqual(plugin.supportedPayloadBand)
  })

  test('better-auth band matches supportedBetterAuthBand', { timeout: 120_000 }, async () => {
    const provider = await import('@payload-auth-link/provider-better-auth')
    expect(doctorBaBand).toEqual(provider.supportedBetterAuthBand)
  })
})
