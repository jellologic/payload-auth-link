// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ProviderLoginView from '../admin/views/ProviderLoginView.js'

// RTL's auto-cleanup keys off a global afterEach, which Vitest does not
// provide with `globals` off — clean up explicitly between renders.
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('provider login view (#55, #72)', () => {
  it('renders both sign-in forms', () => {
    render(<ProviderLoginView authBase="/api/auth" />)
    expect(screen.getByText('Provider sign-in')).toBeDefined()
    expect(screen.getByText('Break-glass local sign-in')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Sign in with provider' })).toBeDefined()
    expect(screen.getByRole('button', { name: 'Sign in locally' })).toBeDefined()
  })

  it('the provider form posts to Better Auth’s email sign-in endpoint (issue #72: /api/auth/sign-in was never a route)', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })))
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderLoginView authBase="/api/auth" />)
    const forms = document.querySelectorAll('form')
    expect(forms.length).toBe(2)
    const providerForm = forms[0]
    if (providerForm === undefined) {
      throw new Error('no provider form')
    }
    fireEvent.submit(providerForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled()
    })
    const firstCall = fetchMock.mock.calls[0]
    if (firstCall === undefined) {
      throw new Error('fetch was not called')
    }
    const [endpoint, init] = firstCall as unknown as [string, RequestInit]
    expect(endpoint).toBe('/api/auth/sign-in/email')
    expect(init.method).toBe('POST')
    expect(init.body).toContain('"email"')
  })

  it('the break-glass form posts to Payload’s own login endpoint', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 401 })))
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderLoginView authBase="/api/auth" />)
    const forms = document.querySelectorAll('form')
    const localForm = forms[1]
    if (localForm === undefined) {
      throw new Error('no local form')
    }
    fireEvent.submit(localForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled()
    })
    const firstCall = fetchMock.mock.calls[0]
    if (firstCall === undefined) {
      throw new Error('fetch was not called')
    }
    const [endpoint] = firstCall as unknown as [string, RequestInit]
    expect(endpoint).toBe('/api/users/login')
    expect(
      await screen.findByText(/check the credentials, or use your identity provider/i)
    ).toBeDefined()
  })
})
