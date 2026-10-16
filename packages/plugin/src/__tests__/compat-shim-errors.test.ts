/**
 * The compatibility shim's error contract (issue #53, #86): the old
 * `payload.betterAuth.api.getSession` returned `null` on every
 * failure, and the shim preserves that — EXCEPT the server API's own
 * gate error, which must surface to the operator instead of reading
 * as "signed out".
 */
import type { Payload } from 'payload'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const getSession = vi.fn<(headers: Headers) => Promise<Record<string, unknown> | null>>()

vi.mock('../server.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../server.js')>()
  return {
    ...actual,
    authLinkServer: () => ({ getSession }),
  }
})

const { createBetterAuthCompatShim } = await import('../compat-shim.js')
const { ServerSessionsDisabledError } = await import('../server.js')

beforeEach(() => {
  getSession.mockReset()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('compat shim getSession error handling', () => {
  const headers = new Headers({ cookie: 'x=1' })

  it('rethrows ServerSessionsDisabledError', async () => {
    const gate = new ServerSessionsDisabledError(false)
    getSession.mockRejectedValue(gate)
    const shim = createBetterAuthCompatShim({} as Payload)
    await expect(shim.api.getSession({ headers })).rejects.toBe(gate)
  })

  it('maps any other failure to null (the legacy contract)', async () => {
    getSession.mockRejectedValue(new Error('provider down'))
    const shim = createBetterAuthCompatShim({} as Payload)
    await expect(shim.api.getSession({ headers })).resolves.toBeNull()
    expect(getSession).toHaveBeenCalledWith(headers)
  })

  it('returns the server session unchanged on success', async () => {
    getSession.mockResolvedValue({ id: 'u1' })
    const shim = createBetterAuthCompatShim({} as Payload)
    await expect(shim.api.getSession({ headers })).resolves.toEqual({ id: 'u1' })
  })
})
