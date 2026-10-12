// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

// RTL's auto-cleanup keys off a global afterEach, which Vitest does not
// provide with `globals` off — clean up explicitly between renders.
afterEach(() => {
  cleanup()
})
import type { SessionUser } from '@payload-auth-link/core'
import { AuthLinkProvider } from '../provider.js'
import { RequireRoles, SignInButton, SignOutButton, UserMenu } from '../components.js'

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

function withinProvider(
  children: ReactNode,
  options?: { fetchImpl?: ReturnType<typeof stubFetch>; initialUser?: SessionUser | null }
): void {
  const fetchImpl = options?.fetchImpl ?? stubFetch(() => jsonResponse({ user }))
  if (options && 'initialUser' in options) {
    render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={options.initialUser}>
        {children}
      </AuthLinkProvider>
    )
    return
  }
  render(<AuthLinkProvider fetchImpl={fetchImpl}>{children}</AuthLinkProvider>)
}

describe('SignInButton', () => {
  it('links to the sign-in page by default', () => {
    render(<SignInButton />)
    const link = screen.getByText('Sign in')
    expect(link.tagName).toBe('A')
    expect(link.getAttribute('href')).toBe('/sign-in')
  })

  it('honors href, className, and children', () => {
    render(
      <SignInButton href="/login" className="btn">
        Log in
      </SignInButton>
    )
    const link = screen.getByText('Log in')
    expect(link.getAttribute('href')).toBe('/login')
    expect(link.getAttribute('class')).toBe('btn')
  })
})

describe('SignOutButton', () => {
  it('signs out, notifies, and navigates on success', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({ ok: true }))
    const navigate = vi.fn()
    const onSignedOut = vi.fn()
    withinProvider(<SignOutButton redirectTo="/" navigate={navigate} onSignedOut={onSignedOut} />, {
      fetchImpl,
      initialUser: user,
    })
    fireEvent.click(screen.getByText('Sign out'))
    await waitFor(() => {
      expect(onSignedOut).toHaveBeenCalledTimes(1)
    })
    expect(navigate).toHaveBeenCalledWith('/')
    expect(fetchImpl.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(true)
  })

  it('stays put when revocation fails', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({}, 500))
    const navigate = vi.fn()
    const onSignedOut = vi.fn()
    withinProvider(<SignOutButton redirectTo="/" navigate={navigate} onSignedOut={onSignedOut} />, {
      fetchImpl,
      initialUser: user,
    })
    fireEvent.click(screen.getByText('Sign out'))
    await waitFor(() => {
      expect(fetchImpl.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(true)
    })
    // Let the rejected promise settle; nothing must happen afterwards.
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(onSignedOut).not.toHaveBeenCalled()
    expect(navigate).not.toHaveBeenCalled()
  })
})

describe('UserMenu', () => {
  it('renders nothing while loading', async () => {
    const pending: Array<(value: Response) => void> = []
    const fetchImpl = vi.fn(
      async (): Promise<Response> =>
        new Promise<Response>((resolve) => {
          pending.push(resolve)
        })
    )
    const { container } = render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <UserMenu />
      </AuthLinkProvider>
    )
    expect(container.textContent).toBe('')
    pending[0]?.(jsonResponse({ user }))
    // Settle inside the test so no state update lands after unmount.
    await screen.findByText('user@example.com')
  })

  it('offers sign-in when anonymous', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({}, 401))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <UserMenu signInHref="/login" />
      </AuthLinkProvider>
    )
    const link = await screen.findByText('Sign in')
    expect(link.getAttribute('href')).toBe('/login')
  })

  it('shows the email and signs out when authenticated', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <UserMenu />
      </AuthLinkProvider>
    )
    expect(await screen.findByText('user@example.com')).toBeDefined()
    expect(screen.getByText('Sign out')).toBeDefined()
  })
})

describe('RequireRoles', () => {
  it('gates on every listed role', async () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    render(
      <AuthLinkProvider fetchImpl={fetchImpl}>
        <RequireRoles roles={['admin']} fallback={<span>denied</span>}>
          <span>granted</span>
        </RequireRoles>
      </AuthLinkProvider>
    )
    expect(await screen.findByText('granted')).toBeDefined()
  })

  it('fails closed while loading and when denied', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    const { container } = render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={null}>
        <RequireRoles roles={['owner']} fallback={<span>denied</span>}>
          <span>granted</span>
        </RequireRoles>
      </AuthLinkProvider>
    )
    expect(container.textContent).toBe('denied')
  })

  it('renders nothing by default when denied', () => {
    const fetchImpl = stubFetch(() => jsonResponse({ user }))
    const { container } = render(
      <AuthLinkProvider fetchImpl={fetchImpl} initialUser={null}>
        <RequireRoles roles={['owner']}>
          <span>granted</span>
        </RequireRoles>
      </AuthLinkProvider>
    )
    expect(container.textContent).toBe('')
  })
})
