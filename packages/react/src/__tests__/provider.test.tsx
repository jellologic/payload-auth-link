// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { SessionUser } from '@payload-auth-link/core'
import { AuthLinkProvider, useAuthLink, useHasRoles } from '../provider.js'

// RTL's auto-cleanup keys off a global afterEach, which Vitest does not
// provide with `globals` off — clean up explicitly between renders.
afterEach(() => {
  cleanup()
})

const user: SessionUser = {
  id: 'user-1',
  collection: 'users',
  email: 'user@example.com',
  roles: ['member', 'admin'],
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function stubFetch(handler: (input: string, init?: RequestInit) => Response | Error) {
  return vi.fn((input: string, init?: RequestInit): Promise<Response> => {
    const result = handler(input, init)
    return result instanceof Error ? Promise.reject(result) : Promise.resolve(result)
  })
}

function StatusProbe(): ReactNode {
  const { user: current, status } = useAuthLink()
  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="email">{current?.email ?? 'none'}</span>
    </div>
  )
}

function RolesProbe({ roles }: { roles: readonly string[] }): ReactNode {
  return <span data-testid="has-roles">{useHasRoles(...roles) ? 'yes' : 'no'}</span>
}

describe('AuthLinkProvider', () => {
  it('loads the session on mount', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <StatusProbe />
      </AuthLinkProvider>
    )
    expect(screen.getByTestId('status').textContent).toBe('loading')
    await waitFor(() => {
      expect(screen.getByTestId('status').textContent).toBe('authenticated')
    })
    expect(screen.getByTestId('email').textContent).toBe('user@example.com')
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('goes anonymous when no session exists', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({ error: 'nope' }, 401))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <StatusProbe />
      </AuthLinkProvider>
    )
    await waitFor(() => {
      expect(screen.getByTestId('status').textContent).toBe('anonymous')
    })
  })

  it('hydrates from initialUser without fetching', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={user}>
        <StatusProbe />
      </AuthLinkProvider>
    )
    expect(screen.getByTestId('status').textContent).toBe('authenticated')
    expect(screen.getByTestId('email').textContent).toBe('user@example.com')
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('hydrates anonymous from a null initialUser without fetching', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={null}>
        <StatusProbe />
      </AuthLinkProvider>
    )
    expect(screen.getByTestId('status').textContent).toBe('anonymous')
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('refreshes on demand', async () => {
    let current: SessionUser | null = null
    const fetchImpl = stubFetch(() =>
      current ? jsonResponse({ user: current }) : jsonResponse({}, 401)
    )
    function RefreshProbe(): ReactNode {
      const { refresh } = useAuthLink()
      return (
        <button
          type="button"
          onClick={() => {
            void refresh()
          }}
        >
          refresh
        </button>
      )
    }
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <StatusProbe />
        <RefreshProbe />
      </AuthLinkProvider>
    )
    await waitFor(() => {
      expect(screen.getByTestId('status').textContent).toBe('anonymous')
    })
    current = user
    fireEvent.click(screen.getByText('refresh'))
    await waitFor(() => {
      expect(screen.getByTestId('status').textContent).toBe('authenticated')
    })
  })

  it('signOut clears state on success and keeps it on failure', async () => {
    let failRevoke = false
    const outcomes: boolean[] = []
    const fetchImpl = stubFetch((_input, init) => {
      if (init?.method === 'DELETE') {
        return failRevoke ? jsonResponse({}, 500) : jsonResponse({ ok: true })
      }
      return jsonResponse({ user })
    })
    function SignOutProbe(): ReactNode {
      const { signOut } = useAuthLink()
      return (
        <button
          type="button"
          onClick={() => {
            void signOut().then((ok) => outcomes.push(ok))
          }}
        >
          sign out
        </button>
      )
    }
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <StatusProbe />
        <SignOutProbe />
      </AuthLinkProvider>
    )
    await waitFor(() => {
      expect(screen.getByTestId('status').textContent).toBe('authenticated')
    })
    failRevoke = true
    fireEvent.click(screen.getByText('sign out'))
    await waitFor(() => {
      expect(outcomes).toEqual([false])
    })
    expect(screen.getByTestId('status').textContent).toBe('authenticated')
    failRevoke = false
    fireEvent.click(screen.getByText('sign out'))
    await waitFor(() => {
      expect(screen.getByTestId('status').textContent).toBe('anonymous')
    })
    expect(outcomes).toEqual([false, true])
  })
})

describe('useAuthLink', () => {
  it('throws outside the provider', () => {
    const silenced = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      expect(() => render(<StatusProbe />)).toThrow(
        'useAuthLink must be used within AuthLinkProvider'
      )
    } finally {
      silenced.mockRestore()
    }
  })
})

describe('useHasRoles', () => {
  it('passes when every listed role is held', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={user}>
        <RolesProbe roles={['admin', 'member']} />
      </AuthLinkProvider>
    )
    expect(screen.getByTestId('has-roles').textContent).toBe('yes')
  })

  it('fails when any listed role is missing', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={user}>
        <RolesProbe roles={['admin', 'owner']} />
      </AuthLinkProvider>
    )
    expect(screen.getByTestId('has-roles').textContent).toBe('no')
  })

  it('fails closed when anonymous', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={null}>
        <RolesProbe roles={['admin']} />
      </AuthLinkProvider>
    )
    expect(screen.getByTestId('has-roles').textContent).toBe('no')
  })
})
