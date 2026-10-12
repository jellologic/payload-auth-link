import type { SessionUser } from '@payload-auth-link/core'
import type { SessionVerifier } from '@payload-auth-link/web'
import { describe, expect, it, vi } from 'vitest'
import { getSessionUserFromRequest } from '../server.js'

const user: SessionUser = {
  id: 'user-1',
  collection: 'users',
  email: 'user@example.com',
  roles: ['member'],
}

describe('getSessionUserFromRequest', () => {
  it('forwards request headers to the verifier', async () => {
    const verify: SessionVerifier = vi.fn((): Promise<SessionUser | null> => Promise.resolve(user))
    const request = new Request('http://localhost:3200/', {
      headers: { cookie: 'better-auth.session_token=abc' },
    })
    await expect(getSessionUserFromRequest(request, verify)).resolves.toBe(user)
    expect(verify).toHaveBeenCalledWith(request.headers)
  })

  it('passes verifier nulls through (fail closed)', async () => {
    const verify: SessionVerifier = vi.fn((): Promise<SessionUser | null> => Promise.resolve(null))
    await expect(
      getSessionUserFromRequest(new Request('http://localhost:3200/'), verify)
    ).resolves.toBeNull()
  })
})
