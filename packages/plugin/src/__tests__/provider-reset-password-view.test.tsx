// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ProviderResetPasswordView, {
  readResetToken,
} from '../admin/views/ProviderResetPasswordView.js'

// RTL's auto-cleanup keys off a global afterEach, which Vitest does not
// provide with `globals` off — clean up explicitly between renders.
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function stubLocation(href: string): void {
  vi.stubGlobal('location', new URL(href))
}

function submitProviderForm(): void {
  const form = document.querySelectorAll('form')[0]
  if (form === undefined) {
    throw new Error('no provider form')
  }
  fireEvent.submit(form)
}

/** The JSON body the view sent — a string by construction. */
function bodyText(init: RequestInit): string {
  const body = init.body
  if (typeof body !== 'string') {
    throw new Error(`unexpected fetch body type: ${typeof body}`)
  }
  return body
}

describe('provider reset-password view (issue #121)', () => {
  describe('readResetToken', () => {
    it('reads the Better Auth redirect query token, then the path segment', () => {
      stubLocation('https://app.test/admin/reset?token=abc123')
      expect(readResetToken('/admin')).toBe('abc123')
      stubLocation('https://app.test/admin/reset/tok456')
      expect(readResetToken('/admin')).toBe('tok456')
      stubLocation('https://app.test/cms/reset?token=abc123')
      expect(readResetToken('/cms')).toBe('abc123')
      // No token anywhere: the login route is not a reset token.
      stubLocation('https://app.test/admin/login')
      expect(readResetToken('/admin')).toBe(null)
    })
  })

  it('asks for a reset email when the token is missing', () => {
    stubLocation('https://app.test/admin/reset')
    render(<ProviderResetPasswordView authBase="/api/auth" />)
    expect(screen.getByText(/needs the token from a reset email/i)).toBeDefined()
    expect(
      screen.getByRole('link', { name: 'the forgot-password page' }).getAttribute('href')
    ).toBe('/admin/forgot')
    expect(document.querySelectorAll('form').length).toBe(0)
    cleanup()
    // A customized `routes.admin` carries into the link.
    stubLocation('https://app.test/cms/reset')
    render(<ProviderResetPasswordView adminRoute="/cms" authBase="/api/auth" />)
    expect(
      screen.getByRole('link', { name: 'the forgot-password page' }).getAttribute('href')
    ).toBe('/cms/forgot')
  })

  it('submits the token and the new password to the provider reset endpoint and confirms', async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(new Response(JSON.stringify({ status: true }), { status: 200 }))
    )
    vi.stubGlobal('fetch', fetchMock)
    stubLocation('https://app.test/admin/reset?token=tok123')
    render(<ProviderResetPasswordView authBase="/api/auth" />)
    const [password, confirm] = screen.getAllByLabelText(/password/i)
    if (password === undefined || confirm === undefined) {
      throw new Error('password fields missing')
    }
    fireEvent.change(password, { target: { value: 'new-secret' } })
    fireEvent.change(confirm, { target: { value: 'new-secret' } })
    submitProviderForm()
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled()
    })
    const call = fetchMock.mock.calls[0]
    if (call === undefined) {
      throw new Error('fetch was not called')
    }
    const [endpoint, init] = call as unknown as [string, RequestInit]
    expect(endpoint).toBe('/api/auth/reset-password')
    expect(init.method).toBe('POST')
    expect(JSON.parse(bodyText(init))).toEqual({ token: 'tok123', newPassword: 'new-secret' })
    expect(await screen.findByText('Password updated')).toBeDefined()
    expect(screen.getByRole('link', { name: 'the admin sign-in' }).getAttribute('href')).toBe(
      '/admin/login'
    )
  })

  it('refuses mismatched passwords without a request', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    stubLocation('https://app.test/admin/reset?token=tok123')
    render(<ProviderResetPasswordView authBase="/api/auth" />)
    const [password, confirm] = screen.getAllByLabelText(/password/i)
    if (password === undefined || confirm === undefined) {
      throw new Error('password fields missing')
    }
    fireEvent.change(password, { target: { value: 'new-secret' } })
    fireEvent.change(confirm, { target: { value: 'other' } })
    submitProviderForm()
    expect(await screen.findByText('Passwords do not match')).toBeDefined()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('renders the provider error for an invalid or expired token', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 400 })))
    vi.stubGlobal('fetch', fetchMock)
    stubLocation('https://app.test/admin/reset?token=dead')
    render(<ProviderResetPasswordView authBase="/api/auth" />)
    submitProviderForm()
    expect(
      await screen.findByText(/the link is invalid or has expired/i, {
        selector: '.provider-reset__error',
      })
    ).toBeDefined()
    // Failure keeps the form up for a corrected entry or retry.
    expect(screen.getByRole('button', { name: 'Set new password' })).toBeDefined()
  })

  it('uses the configured auth base, reset endpoint, and admin route', async () => {
    // Both attempts fail (400 provider, 403 local) so both forms stay
    // mounted — this test derives endpoints and bodies, not success.
    const fetchMock = vi.fn((input: unknown) =>
      Promise.resolve(
        new Response(null, { status: String(input).startsWith('/backend/auth') ? 400 : 403 })
      )
    )
    vi.stubGlobal('fetch', fetchMock)
    stubLocation('https://app.test/cms/reset/tok456')
    render(
      <ProviderResetPasswordView
        adminRoute="/cms"
        authBase="/backend/auth"
        resetEndpoint="/backend/operators/reset-password"
      />
    )
    const [password, confirm] = screen.getAllByLabelText(/password/i)
    if (password === undefined || confirm === undefined) {
      throw new Error('password fields missing')
    }
    fireEvent.change(password, { target: { value: 'new-secret' } })
    fireEvent.change(confirm, { target: { value: 'new-secret' } })
    // The path-segment token fallback feeds the provider form…
    submitProviderForm()
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/backend/auth/reset-password', expect.anything())
    })
    const first = fetchMock.mock.calls[0]
    if (first === undefined) {
      throw new Error('fetch was not called')
    }
    const firstInit = (first as unknown as [unknown, RequestInit])[1]
    expect(JSON.parse(bodyText(firstInit))).toEqual({
      token: 'tok456',
      newPassword: 'new-secret',
    })
    // …and the same fields drive the break-glass local form.
    const localForm = document.querySelectorAll('form')[1]
    if (localForm === undefined) {
      throw new Error('no local form')
    }
    fireEvent.submit(localForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/backend/operators/reset-password', expect.anything())
    })
    const second = fetchMock.mock.calls[1]
    if (second === undefined) {
      throw new Error('local fetch was not called')
    }
    const secondInit = (second as unknown as [unknown, RequestInit])[1]
    expect(JSON.parse(bodyText(secondInit))).toEqual({
      password: 'new-secret',
      token: 'tok456',
    })
  })

  it('surfaces the local break-glass refusal for provider-linked accounts', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 403 })))
    vi.stubGlobal('fetch', fetchMock)
    stubLocation('https://app.test/admin/reset?token=tok123')
    render(<ProviderResetPasswordView authBase="/api/auth" />)
    const localForm = document.querySelectorAll('form')[1]
    if (localForm === undefined) {
      throw new Error('no local form')
    }
    fireEvent.submit(localForm)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/users/reset-password', expect.anything())
    })
    expect(
      await screen.findByText(/the account is provider-linked/i, {
        selector: '.provider-reset__error',
      })
    ).toBeDefined()
  })
})
