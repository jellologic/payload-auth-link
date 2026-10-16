/**
 * The server registry is shared by every loaded copy of server.ts.
 * Under TanStack Start the admin and API route graphs each load their
 * own copy of the plugin modules but share one cached Payload: when the
 * admin copy's `onInit` registers the instance, `authLinkServer(payload)`
 * from the API copy must still find it (it used to throw
 * AuthLinkServerMissingError).
 */
import { nullLogger } from '@payload-auth-link/core'
import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'
import { wireOptions } from '../options.js'
import { createStubProvider } from './stub-provider.js'

type ServerModule = typeof import('../server.js')

async function freshCopy(): Promise<ServerModule> {
  vi.resetModules()
  return import('../server.js')
}

describe('authLinkServer across module copies', () => {
  it('finds an instance registered by another copy of the module', async () => {
    const booting = await freshCopy()
    const serving = await freshCopy()
    expect(serving).not.toBe(booting)
    const payload = {} as Payload
    const wired = wireOptions({
      baseUrl: 'http://auth-link.test',
      roles: ['user', 'admin'],
      defaultRole: 'user',
      roleManagerRoles: ['admin'],
      providers: [createStubProvider().provider],
      logger: nullLogger(),
    })
    booting.registerAuthLinkServer(payload, wired)
    expect(() => serving.authLinkServer(payload)).not.toThrow()
  })

  it('still refuses an instance no copy registered', async () => {
    const serving = await freshCopy()
    expect(() => serving.authLinkServer({} as Payload)).toThrow(serving.AuthLinkServerMissingError)
  })
})
