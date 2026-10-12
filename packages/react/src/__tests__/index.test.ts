import { describe, expect, it, vi } from 'vitest'
import { fetchSessionUser } from '../index.js'

describe('react entrypoint', () => {
  it('serves the session reader contract through the barrel', async () => {
    const fetchImpl = vi.fn(() => Promise.resolve(new Response('nope', { status: 401 })))
    await expect(fetchSessionUser('/api/auth-link/session', fetchImpl)).resolves.toBeNull()
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })
})
