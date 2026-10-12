import { describe, expect, it, vi } from 'vitest'
import { fetchSessionUser, revokeSession } from '../session.js'

const user = { id: 'user-1', collection: 'users', email: 'user@example.com', roles: ['member'] }

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function stubFetch(response: Response | Error) {
  const fetchImpl = vi.fn()
  if (response instanceof Error) {
    fetchImpl.mockRejectedValue(response)
  } else {
    fetchImpl.mockResolvedValue(response)
  }
  return fetchImpl
}

describe('fetchSessionUser', () => {
  it('reads the user from the default endpoint', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    const result = await fetchSessionUser(undefined, fetchImpl)
    expect(result).toEqual(user)
    expect(fetchImpl).toHaveBeenCalledWith('/api/auth-link/session', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { accept: 'application/json' },
    })
  })

  it('honors a custom endpoint', async () => {
    const fetchImpl = stubFetch(jsonResponse({ user }))
    await fetchSessionUser('/custom/session', fetchImpl)
    expect(fetchImpl).toHaveBeenCalledWith(
      '/custom/session',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('fails closed on transport and protocol failures', async () => {
    for (const response of [
      stubFetch(new Error('down')),
      stubFetch(jsonResponse({ error: 'nope' }, 401)),
      stubFetch(jsonResponse({ error: 'nope' }, 500)),
      stubFetch(new Response('not-json{', { status: 200 })),
      stubFetch(jsonResponse([user])),
      stubFetch(jsonResponse({})),
      stubFetch(jsonResponse({ user: { ...user, email: 'bad' } })),
    ]) {
      await expect(fetchSessionUser(undefined, response)).resolves.toBeNull()
    }
  })
})

describe('revokeSession', () => {
  it('sends a CSRF-proofed DELETE to the default endpoint', async () => {
    const fetchImpl = stubFetch(jsonResponse({ ok: true }))
    await expect(revokeSession(undefined, fetchImpl)).resolves.toBe(true)
    expect(fetchImpl).toHaveBeenCalledWith('/api/auth-link/session', {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: { 'x-auth-link-csrf': '1' },
    })
  })

  it('treats already-signed-out as success (idempotent logout)', async () => {
    await expect(revokeSession(undefined, stubFetch(jsonResponse({}, 401)))).resolves.toBe(true)
  })

  it('reports failure instead of lying', async () => {
    await expect(revokeSession(undefined, stubFetch(new Error('down')))).resolves.toBe(false)
    await expect(revokeSession(undefined, stubFetch(jsonResponse({}, 500)))).resolves.toBe(false)
    await expect(revokeSession(undefined, stubFetch(jsonResponse({}, 403)))).resolves.toBe(false)
  })
})
