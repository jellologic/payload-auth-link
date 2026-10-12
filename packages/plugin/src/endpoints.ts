import { expiringCookieOptions, serializeCookie, type ProviderId } from '@payload-auth-link/core'
import type { Endpoint, PayloadRequest } from 'payload'
import { forbidden, jsonResponse, logVerifyFailure, passesCsrf, unauthorized } from './access.js'
import { toPayloadUser } from './mapping.js'
import type { WiredOptions } from './options.js'
import { createServices } from './services.js'

/**
 * Expire every registered provider's session cookies on a logout
 * response. Revoking the server session without clearing the cookies
 * would leave the browser presenting a dead token: optimistic
 * middleware keeps passing it through and the user looks signed in
 * until the cookie naturally expires.
 *
 * The clearing write must carry the cookie's live attributes: a `Secure`
 * cookie (in particular any `__Secure-` name) survives a clearing write
 * without `Secure`, and a custom `Domain`/`Path` needs matching or the
 * overwrite misses. Providers report theirs via
 * `sessionCookieClearOptions`; providers that predate that hook fall back
 * to prefix-derived attributes.
 */
function expireSessionCookies(wired: WiredOptions, response: Response): void {
  for (const id of wired.registry.ids()) {
    const required = wired.registry.require(id)
    if (required.isErr()) {
      continue
    }
    for (const name of required.value.sessionCookieNames) {
      const known = required.value.sessionCookieClearOptions?.(name)
      const clearing =
        known === undefined
          ? expiringCookieOptions(name)
          : { ...known, maxAge: 0, path: known.path ?? '/' }
      response.headers.append('Set-Cookie', serializeCookie(name, '', clearing))
    }
  }
}

/**
 * Best-effort revoke of every OTHER provider session the request
 * presents. Verification stops at the first registered provider with a
 * live session (registry order is precedence), so a browser signed in
 * through two providers would otherwise keep the second session alive
 * server-side after logout. Failures are logged and skipped: the
 * cookies are expired regardless, and one provider being down must not
 * block logout from the others.
 */
async function revokePresentedSessions(
  wired: WiredOptions,
  headers: Headers,
  skip: ProviderId | null
): Promise<void> {
  for (const id of wired.registry.ids()) {
    if (id === skip) {
      continue
    }
    const required = wired.registry.require(id)
    if (required.isErr()) {
      continue
    }
    const provider = required.value
    const current = await provider.getSession(headers)
    if (current.isErr()) {
      wired.logger.warn('logout provider session read failed', { providerId: provider.id })
      continue
    }
    if (!current.value) {
      continue
    }
    const revoked = await provider.revokeSession(current.value.sessionId)
    if (revoked.isErr()) {
      wired.logger.error('logout provider session revoke failed', {
        providerId: provider.id,
        cause: revoked.error.cause ?? revoked.error,
      })
    }
  }
}

/**
 * Plugin endpoints. Custom endpoints are unauthenticated by default, so each
 * handler checks the session explicitly; state-changing handlers additionally
 * require CSRF proof (see `access.ts`).
 */
export function createEndpoints(wired: WiredOptions): Endpoint[] {
  const services = (req: PayloadRequest) => createServices(wired, req.payload)

  return [
    {
      path: '/auth-link/session',
      method: 'get',
      handler: async (req) => {
        const { users, sessions } = services(req)
        const verified = await sessions.verify(req.headers)
        if (verified.isErr()) {
          logVerifyFailure(wired.logger, 'session endpoint', verified.error)
          return unauthorized()
        }
        const found = await users.findById(verified.value.userId)
        if (found.isErr()) {
          wired.logger.error('session endpoint user reload failed', {
            cause: found.error.cause ?? found.error,
          })
          return unauthorized()
        }
        if (!found.value) {
          wired.logger.warn('session endpoint session has no user document')
          return unauthorized()
        }
        return jsonResponse(
          { user: toPayloadUser(found.value, wired.config.map.usersCollection) },
          200
        )
      },
    },
    {
      path: '/auth-link/session',
      method: 'delete',
      handler: async (req) => {
        if (!passesCsrf(req.headers, wired.config.baseUrl)) {
          return forbidden('csrf check failed')
        }
        const { sessions } = services(req)
        const verified = await sessions.verify(req.headers)
        if (verified.isErr()) {
          // Idempotent logout: no live session, but a stale cookie may
          // remain — expire it so the browser stops presenting it.
          logVerifyFailure(wired.logger, 'logout endpoint', verified.error)
          // A provider session may still be live behind a failed verify
          // (expired link, unverified email): revoke it too.
          await revokePresentedSessions(wired, req.headers, null)
          const alreadyOut = unauthorized()
          expireSessionCookies(wired, alreadyOut)
          return alreadyOut
        }
        const revoked = await sessions.revoke(verified.value)
        await revokePresentedSessions(wired, req.headers, verified.value.providerId)
        if (revoked.isErr()) {
          wired.logger.error('session revoke failed', { providerId: verified.value.providerId })
          // Best-effort local logout: the server session may still be
          // live (revocation failed), but expiring the cookies stops
          // the browser presenting it — without this, optimistic
          // middleware keeps passing the dead-or-dying token and the
          // user looks signed in. Only REGISTERED providers' cookies
          // can be cleared: removing a provider from the registry
          // orphans its cookies until natural expiry, so keep removed
          // providers registered through a transition (or clear them
          // out-of-band) rather than dropping them outright.
          const failed = jsonResponse({ error: 'revoke failed' }, 500)
          expireSessionCookies(wired, failed)
          return failed
        }
        const signedOut = jsonResponse({ ok: true }, 200)
        expireSessionCookies(wired, signedOut)
        return signedOut
      },
    },
  ]
}
