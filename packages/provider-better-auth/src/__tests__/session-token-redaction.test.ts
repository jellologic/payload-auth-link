import { nullLogger, type LoggerPort } from '@payload-auth-link/core'
import { describe, expect, it, vi } from 'vitest'
import {
  redactSessionTokens,
  reportSessionTokenExposure,
  resolveRevokeHandle,
  type RedactionHookContext,
} from '../session-token-redaction.js'

const minted = { session: { token: 'tok-new', id: 'sid' }, user: { id: 'u' } }

describe('redactSessionTokens (issue #113)', () => {
  it('leaves hand-off protocols and unknown paths alone', () => {
    const body = { session: { token: 'tok-new' }, token: 'tok-new' }
    expect(redactSessionTokens(undefined, body, minted)).toBeUndefined()
    expect(redactSessionTokens('/multi-session/set-active', body, minted)).toBeUndefined()
    expect(
      redactSessionTokens('/multi-session/list-device-sessions', [body], minted)
    ).toBeUndefined()
    expect(redactSessionTokens('/one-time-token/verify', body, minted)).toBeUndefined()
  })

  it('strips session.token from /get-session and nothing else', () => {
    expect(
      redactSessionTokens(
        '/get-session',
        { session: { id: 's', token: 't', expiresAt: 'x' }, user: { id: 'u' } },
        null
      )
    ).toEqual({ session: { id: 's', expiresAt: 'x' }, user: { id: 'u' } })
    expect(redactSessionTokens('/get-session', null, null)).toBeUndefined()
    expect(redactSessionTokens('/get-session', { session: { id: 's' } }, null)).toBeUndefined()
    expect(redactSessionTokens('/get-session', { session: 'odd' }, null)).toBeUndefined()
  })

  it('strips token from every /list-sessions entry', () => {
    expect(
      redactSessionTokens(
        '/list-sessions',
        [{ id: 'a', token: 'ta' }, { id: 'b', token: 'tb' }, 'odd'],
        null
      )
    ).toEqual([{ id: 'a' }, { id: 'b' }, 'odd'])
    expect(redactSessionTokens('/list-sessions', [{ id: 'a' }], null)).toBeUndefined()
    expect(redactSessionTokens('/list-sessions', { not: 'an array' }, null)).toBeUndefined()
  })

  it('strips the minted token and every session-shaped token from other bodies', () => {
    expect(
      redactSessionTokens('/sign-in/email', { token: 'tok-new', user: { id: 'u' } }, minted)
    ).toEqual({ user: { id: 'u' } })
    expect(
      redactSessionTokens(
        '/passkey/verify-authentication',
        { session: { id: 'sid', token: 'tok-new' } },
        minted
      )
    ).toEqual({ session: { id: 'sid' } })
    expect(
      redactSessionTokens('/x', { token: 'tok-new', session: { token: 'tok-new' } }, minted)
    ).toEqual({ session: {} })
    // Default-deny (issue #116): a session's token goes whatever minted it.
    expect(redactSessionTokens('/x', { session: { token: 'other' } }, minted)).toEqual({
      session: {},
    })
    // A value that only shares the key name (jwt `/token`, …) stays.
    expect(redactSessionTokens('/token', { token: 'a.jwt.value' }, minted)).toBeUndefined()
    expect(redactSessionTokens('/token', { token: 'a.jwt.value' }, null)).toBeUndefined()
    // No minted session and no `user`: nothing marks the token a session's.
    expect(redactSessionTokens('/sign-in/email', { token: 'tok-new' }, null)).toBeUndefined()
    expect(
      redactSessionTokens('/sign-in/email', { token: 'tok-new' }, { session: { token: '' } })
    ).toBeUndefined()
    expect(redactSessionTokens('/sign-in/email', 'text', minted)).toBeUndefined()
    expect(redactSessionTokens('/sign-in/email', new Response('{}'), minted)).toBeUndefined()
  })

  it('strips the token of a second-factor body (step-up returns the PRESENTED token)', () => {
    // `/two-factor/verify-*` answers `{ token, user }` with the token of
    // the session it stepped up — not a newly minted one (issue #116).
    for (const path of [
      '/two-factor/verify-totp',
      '/two-factor/verify-otp',
      '/two-factor/verify-backup-code',
    ]) {
      expect(redactSessionTokens(path, { token: 'presented', user: { id: 'u' } }, null)).toEqual({
        user: { id: 'u' },
      })
    }
  })

  it('strips token from session rows nested anywhere (admin listings, impersonation)', () => {
    const row = { id: 's1', token: 't1', userId: 'u', expiresAt: 'x' }
    expect(
      redactSessionTokens('/admin/list-user-sessions', { sessions: [row, { id: 's2' }] }, null)
    ).toEqual({ sessions: [{ id: 's1', userId: 'u', expiresAt: 'x' }, { id: 's2' }] })
    expect(redactSessionTokens('/admin/whatever', [{ nested: { list: [row] } }], null)).toEqual([
      { nested: { list: [{ id: 's1', userId: 'u', expiresAt: 'x' }] } },
    ])
    expect(
      redactSessionTokens('/admin/impersonate-user', { session: row, user: { id: 'u' } }, null)
    ).toEqual({ session: { id: 's1', userId: 'u', expiresAt: 'x' }, user: { id: 'u' } })
    // A session row nesting another session row loses both tokens.
    expect(
      redactSessionTokens('/x', { token: 't', userId: 'u', session: { token: 'n' } }, null)
    ).toEqual({ userId: 'u', session: {} })
    // Unchanged bodies keep their identity (no re-serialization).
    expect(
      redactSessionTokens('/x', { a: [1, 'two', null], at: new Date(0), deep: { ok: true } }, null)
    ).toBeUndefined()
    // A pathological depth stops the walk instead of recursing forever.
    let deep: Record<string, unknown> = { token: 't', userId: 'u' }
    for (let level = 0; level < 20; level += 1) {
      deep = { next: deep }
    }
    expect(redactSessionTokens('/x', deep, null)).toBeUndefined()
  })
})

describe('resolveRevokeHandle (issue #113)', () => {
  function ctx(body: unknown, findOne?: (input: unknown) => Promise<unknown>) {
    return {
      body,
      context: findOne === undefined ? {} : { adapter: { findOne } },
    } as unknown as RedactionHookContext
  }

  it('resolves a session row id to its token', async () => {
    const findOne = vi.fn(() => Promise.resolve({ id: 'sid', token: 'tok' }))
    await expect(resolveRevokeHandle(ctx({ token: 'sid' }, findOne))).resolves.toEqual({
      context: { body: { token: 'tok' } },
    })
    expect(findOne).toHaveBeenCalledWith({
      model: 'session',
      where: [{ field: 'id', value: 'sid' }],
    })
  })

  it('passes anything else through unchanged', async () => {
    const none = () => Promise.resolve(null)
    await expect(resolveRevokeHandle(ctx({ token: 'raw-token' }, none))).resolves.toBeUndefined()
    await expect(
      resolveRevokeHandle(ctx({ token: 'sid' }, () => Promise.resolve({ token: '' })))
    ).resolves.toBeUndefined()
    await expect(resolveRevokeHandle(ctx({ token: '' }, none))).resolves.toBeUndefined()
    await expect(resolveRevokeHandle(ctx('body', none))).resolves.toBeUndefined()
    await expect(resolveRevokeHandle(ctx({ token: 'sid' }))).resolves.toBeUndefined()
  })
})

describe('reportSessionTokenExposure (issue #113)', () => {
  function logger(): { port: LoggerPort; warn: ReturnType<typeof vi.fn> } {
    const warn = vi.fn()
    return { port: { ...nullLogger(), warn }, warn }
  }

  it('warns for bearer() without requireSignature next to an exposing surface', () => {
    const exposed = logger()
    reportSessionTokenExposure([{ id: 'bearer' }], true, exposed.port)
    expect(exposed.warn).toHaveBeenCalledTimes(1)
    expect(exposed.warn).toHaveBeenCalledWith(
      expect.stringContaining('exposeSessionTokens: true'),
      expect.objectContaining({ setting: 'bearer' })
    )
    const multi = logger()
    reportSessionTokenExposure(
      [{ id: 'bearer', options: { requireSignature: false } }, { id: 'multi-session' }],
      true,
      multi.port
    )
    expect(multi.warn).toHaveBeenCalledTimes(2)
    expect(multi.warn).toHaveBeenCalledWith(
      expect.stringContaining('list-device-sessions'),
      expect.anything()
    )
  })

  it('stays quiet without bearer(), with requireSignature, or with nothing exposed', () => {
    const quiet = logger()
    reportSessionTokenExposure([{ id: 'multi-session' }], true, quiet.port)
    reportSessionTokenExposure(
      [{ id: 'bearer', options: { requireSignature: true } }, { id: 'multi-session' }],
      true,
      quiet.port
    )
    reportSessionTokenExposure([{ id: 'bearer' }], false, quiet.port)
    expect(quiet.warn).not.toHaveBeenCalled()
  })
})
