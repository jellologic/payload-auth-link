import type { SessionUser } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import { createSessionLoader } from '../loader.js'

const user: SessionUser = {
  id: 'user-1',
  collection: 'users',
  email: 'user@example.com',
  roles: ['member'],
}

describe('createSessionLoader', () => {
  it('returns loader data hydrating the initial user', async () => {
    const getSessionUser = vi.fn((): Promise<SessionUser | null> => Promise.resolve(user))
    await expect(createSessionLoader(getSessionUser)()).resolves.toEqual({ initialUser: user })
    expect(getSessionUser).toHaveBeenCalledTimes(1)
  })

  it('hydrates null for anonymous visitors', async () => {
    const getSessionUser = vi.fn((): Promise<SessionUser | null> => Promise.resolve(null))
    await expect(createSessionLoader(getSessionUser)()).resolves.toEqual({ initialUser: null })
  })
})
