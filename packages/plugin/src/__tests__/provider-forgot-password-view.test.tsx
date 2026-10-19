// @vitest-environment happy-dom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ProviderForgotPasswordView from '../admin/views/ProviderForgotPasswordView.js'

// RTL's auto-cleanup keys off a global afterEach, which Vitest does not
// provide with `globals` off — clean up explicitly between renders.
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function lastCall(fetchMock: ReturnType<typeof vi.fn>): { endpoint: unknown; init: RequestInit } {
  const call = fetchMock.mock.calls.at(-1)
  if (call === undefined) {
    throw new Error('fetch was not called')
  }
  const [endpoint, init] = call as unknown as [unknown, RequestInit]
  return { endpoint, init }
}

/** The JSON body the view sent — a string by construction. */
function bodyText(init: RequestInit): string {
  const body = init.body
  if (typeof body !== 'string') {
    throw new Error(`unexpected fetch body type: ${typeof body}`)
  }
  return body
}

describe('provider forgot-password view (issue #121)', () => {
  it('renders both request forms', () => {
    render(<ProviderForgotPasswordView authBase="/api/auth" />)
    expect(screen.getByText('Provider password reset')).toBeDefined()
    expect(screen.getByText('Break-glass local reset request')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Send reset email' })).toBeDefined()
    expect(screen.getByRole('button', { name: 'Send local reset email' })).toBeDefined()
  })

  it('submits the email to the provider request endpoint with the reset redirect and confirms', async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ status: true, message: 'If this email exists…' }), {
          status: 200,
        })
      )
    )
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderForgotPasswordView authBase="/api/auth" />)
    const email = screen.getAllByLabelText('Email')[0]
    if (email === undefined) {
      throw new Error('no provider email field')
    }
    fireEvent.change(email, { target: { value: 'linked@example.com' } })
    fireEvent.submit(document.querySelectorAll('form')[0] as HTMLFormElement)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalled()
    })
    const { endpoint, init } = lastCall(fetchMock)
    expect(endpoint).toBe('/api/auth/request-password-reset')
    expect(init.method).toBe('POST')
    expect(JSON.parse(bodyText(init))).toEqual({
      email: 'linked@example.com',
      redirectTo: '/admin/reset',
    })
    expect(
      await screen.findByText(/a reset link is on its way/i, {
        selector: '.provider-forgot__confirmation p',
      })
    ).toBeDefined()
  })

  it('links the reset email redirect at the configured reset route and endpoints', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })))
    vi.stubGlobal('fetch', fetchMock)
    render(
      <ProviderForgotPasswordView
        adminRoute="/cms"
        authBase="/backend/auth"
        forgotEndpoint="/backend/operators/forgot-password"
        resetRoute="/cms/password-reset"
      />
    )
    expect(
      screen.getByRole('link', { name: 'the admin password reset page' }).getAttribute('href')
    ).toBe('/cms/password-reset')
    expect(screen.getByRole('link', { name: 'the admin sign-in' }).getAttribute('href')).toBe(
      '/cms/login'
    )
    fireEvent.submit(document.querySelectorAll('form')[1] as HTMLFormElement)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/backend/operators/forgot-password',
        expect.anything()
      )
    })
    const { init } = lastCall(fetchMock)
    expect(JSON.parse(bodyText(init))).toEqual({ email: '' })
  })

  it('renders error responses from the provider endpoint', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 429 })))
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderForgotPasswordView authBase="/api/auth" />)
    fireEvent.submit(document.querySelectorAll('form')[0] as HTMLFormElement)
    expect(
      await screen.findByText(/too many reset requests/i, {
        selector: '.provider-forgot__error',
      })
    ).toBeDefined()
    // The form stays up so the request can be retried.
    expect(screen.getByRole('button', { name: 'Send reset email' })).toBeDefined()
  })

  it('surfaces the local break-glass refusal for provider-linked accounts', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 403 })))
    vi.stubGlobal('fetch', fetchMock)
    render(<ProviderForgotPasswordView authBase="/api/auth" />)
    fireEvent.submit(document.querySelectorAll('form')[1] as HTMLFormElement)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/users/forgot-password', expect.anything())
    })
    expect(
      await screen.findByText(/the account may be provider-linked/i, {
        selector: '.provider-forgot__error',
      })
    ).toBeDefined()
  })
})
