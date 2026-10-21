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

  it('links to the provider forgot-password view (#121)', () => {
    render(<ProviderLoginView adminRoute="/cms" authBase="/api/auth" />)
    expect(
      screen.getByRole('link', { name: 'Reset it through the provider' }).getAttribute('href')
    ).toBe('/cms/forgot')
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

  it('uses the configured endpoints, admin route, and sign-in link', async () => {
    const fetchMock = vi.fn((input: string) =>
      Promise.resolve(
        new Response(input.endsWith('/sign-in/email') ? '{}' : null, {
          status: input.endsWith('/sign-in/email') ? 200 : 401,
        })
      )
    )
    vi.stubGlobal('fetch', fetchMock)
    const assign = vi.fn()
    const location = { href: '' }
    Object.defineProperty(location, 'href', { set: assign, get: () => '' })
    vi.stubGlobal('location', location)
    render(
      <ProviderLoginView
        authBase="/backend/auth"
        loginEndpoint="/backend/operators/login"
        adminRoute="/cms"
        signInPath="/login"
      />
    )
    expect(screen.getByRole('link', { name: 'app sign-in page' }).getAttribute('href')).toBe(
      '/login'
    )
    const [providerForm, localForm] = [...document.querySelectorAll('form')]
    if (providerForm === undefined || localForm === undefined) {
      throw new Error('forms missing')
    }
    fireEvent.submit(localForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/backend/operators/login', expect.anything())
    })
    fireEvent.submit(providerForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/backend/auth/sign-in/email', expect.anything())
    })
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith('/cms')
    })
  })
})

describe('provider login view alternative methods (#157)', () => {
  it('renders nothing new without the port facts — the view is unchanged', () => {
    render(<ProviderLoginView authBase="/api/auth" />)
    expect(screen.queryByText('Alternative sign-in methods')).toBeNull()
    expect(document.querySelectorAll('form').length).toBe(2)
    expect(screen.queryByRole('button', { name: /Continue with/ })).toBeNull()
    // The two forms keep their original order and endpoints: the
    // provider form first, break-glass second.
    const [providerForm, localForm] = [...document.querySelectorAll('form')]
    expect(providerForm?.querySelector('input[name="password"]')).toBeDefined()
    expect(localForm?.querySelector('input[name="password"]')).toBeDefined()
  })

  it('renders social buttons and the magic-link form above the provider form', () => {
    render(
      <ProviderLoginView
        adminRoute="/cms"
        authBase="/api/auth"
        magicLink
        socialProviders={['google', 'facebook']}
      />
    )
    const methods = screen.getByText('Alternative sign-in methods')
    const providerHeading = screen.getByText('Provider sign-in')
    // The section PRECEDES the provider form in the DOM.
    expect(
      methods.compareDocumentPosition(providerHeading) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Continue with Google' })).toBeDefined()
    expect(screen.getByRole('button', { name: 'Continue with Facebook' })).toBeDefined()
    // Magic-link form, provider form, break-glass form.
    expect(document.querySelectorAll('form').length).toBe(3)
    // The break-glass and provider forms survive unchanged below.
    expect(screen.getByText('Break-glass local sign-in')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Sign in with provider' })).toBeDefined()
  })

  it('social buttons navigate to the provider social sign-in endpoint with the admin callback', () => {
    const assign = vi.fn()
    const location = { href: '' }
    Object.defineProperty(location, 'href', { set: assign, get: () => '' })
    vi.stubGlobal('location', location)
    render(
      <ProviderLoginView adminRoute="/cms" authBase="/api/auth" socialProviders={['google']} />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Continue with Google' }))
    expect(assign).toHaveBeenCalledWith(
      '/api/auth/sign-in/social?provider=google&callbackURL=%2Fcms'
    )
  })

  it('the magic-link form posts email + callbackURL and swaps to the sent state', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })))
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderLoginView adminRoute="/cms" authBase="/api/auth" magicLink />)
    const magicLinkForm = document.querySelectorAll('form')[0]
    if (magicLinkForm === undefined) {
      throw new Error('no magic-link form')
    }
    const emailInput = magicLinkForm.querySelector('input[name="email"]')
    if (emailInput === null || !(emailInput instanceof HTMLInputElement)) {
      throw new Error('no email input')
    }
    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.submit(magicLinkForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/auth/sign-in/magic-link',
        expect.objectContaining({ method: 'POST' })
      )
    })
    const firstCall = fetchMock.mock.calls[0]
    if (firstCall === undefined) {
      throw new Error('fetch was not called')
    }
    const init = (firstCall as unknown as [string, RequestInit])[1]
    expect(init.body).toContain('"email":"user@example.com"')
    expect(init.body).toContain('"callbackURL":"/cms"')
    expect(await screen.findByText(/check your email/i)).toBeDefined()
    // The sent state replaces the form — no resubmit surface.
    expect(document.querySelectorAll('form').length).toBe(2)
  })

  it('a failed magic-link request surfaces the error and keeps the form', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 500 })))
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderLoginView authBase="/api/auth" magicLink />)
    const magicLinkForm = document.querySelectorAll('form')[0]
    if (magicLinkForm === undefined) {
      throw new Error('no magic-link form')
    }
    fireEvent.submit(magicLinkForm)
    expect(await screen.findByText(/Sign-in failed \(500\)/)).toBeDefined()
    expect(document.querySelectorAll('form').length).toBe(3)
  })
})
