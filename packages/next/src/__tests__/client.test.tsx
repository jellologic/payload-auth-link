// @vitest-environment happy-dom
import { act, cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthLinkProvider } from '@payload-auth-link/react'
import { useAuthLinkRefresh } from '../client.js'

afterEach(() => {
  cleanup()
})

const routerRefresh = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: routerRefresh }),
}))

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('useAuthLinkRefresh', () => {
  it('refreshes the session and revalidates the router', async () => {
    const user = {
      id: 'user-1',
      collection: 'users',
      email: 'user@example.com',
      roles: ['member'],
    }
    const fetchImpl = vi.fn((): Promise<Response> => Promise.resolve(jsonResponse({ user })))
    let refreshAll: (() => Promise<void>) | undefined
    function Probe(): null {
      refreshAll = useAuthLinkRefresh()
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
    expect(routerRefresh).toHaveBeenCalledTimes(1)
  })
})
