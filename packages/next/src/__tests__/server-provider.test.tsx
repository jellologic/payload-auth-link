import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthLinkProvider } from '@payload-auth-link/react'
import type { SessionUser } from '@payload-auth-link/core'
import { AuthLinkServerProvider } from '../server-provider.js'

const seen: Headers[] = []

vi.mock('next/headers', () => ({
  headers: (): Promise<Headers> => {
    const value = new Headers({ cookie: 'better-auth.session_token=abc' })
    seen.push(value)
    return Promise.resolve(value)
  },
}))

// Shared mock state is reset per test: no test may inherit another's
// recorded headers or call counts.
beforeEach(() => {
  vi.clearAllMocks()
  seen.length = 0
})

const user: SessionUser = {
  id: 'user-1',
  collection: 'users',
  email: 'user@example.com',
  roles: ['member'],
}

describe('AuthLinkServerProvider', () => {
  it('verifies with the live headers and hydrates the client provider', async () => {
    const verify = vi.fn((): Promise<SessionUser | null> => Promise.resolve(user))
    const element = await AuthLinkServerProvider({
      children: 'page',
      verify,
      sessionEndpoint: '/custom/session',
    })
    expect(verify).toHaveBeenCalledTimes(1)
    expect(verify).toHaveBeenCalledWith(seen[0])
    expect(element.type).toBe(AuthLinkProvider)
    const props = element.props as { initialUser?: unknown; sessionEndpoint?: unknown }
    expect(props.initialUser).toEqual(user)
    expect(props.sessionEndpoint).toBe('/custom/session')
  })

  it('hydrates anonymous when verification finds no session', async () => {
    const verify = vi.fn((): Promise<SessionUser | null> => Promise.resolve(null))
    const element = await AuthLinkServerProvider({ children: 'page', verify })
    expect(element.type).toBe(AuthLinkProvider)
    const props = element.props as { initialUser?: unknown }
    expect(props.initialUser).toBeNull()
    // Inherits nothing from the previous test: exactly this render's read.
    expect(seen).toHaveLength(1)
    expect(verify).toHaveBeenCalledWith(seen[0])
  })
})
