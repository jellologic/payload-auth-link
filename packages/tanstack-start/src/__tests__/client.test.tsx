// @vitest-environment happy-dom
import { act, cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthLinkProvider } from '@payload-auth-link/react'
import { useAuthLinkRefreshStart } from '../client.js'

afterEach(() => {
  cleanup()
})

const routerInvalidate = vi.fn((): Promise<void> => Promise.resolve())

vi.mock('@tanstack/react-router', () => ({
  useRouter: () => ({ invalidate: routerInvalidate }),
}))

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('useAuthLinkRefreshStart', () => {
  it('refreshes the session and invalidates router loaders', async () => {
    const user = {
      id: 'user-1',
      collection: 'users',
      email: 'user@example.com',
      roles: ['member'],
    }
    const fetchImpl = vi.fn((): Promise<Response> => Promise.resolve(jsonResponse({ user })))
    let refreshAll: (() => Promise<void>) | undefined
    function Probe(): null {
      refreshAll = useAuthLinkRefreshStart()
      return null
    }
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={null}>
        <Probe />
      </AuthLinkProvider>
    )
    expect(refreshAll).toBeDefined()
    await act(async () => {
      await refreshAll?.()
    })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    expect(routerInvalidate).toHaveBeenCalledTimes(1)
  })
})
