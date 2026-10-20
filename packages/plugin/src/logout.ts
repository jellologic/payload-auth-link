import { isRecord } from '@payload-auth-link/core'
import type { IdentityProviderPort } from '@payload-auth-link/core'
import { Ok, ResultAsync } from 'neverthrow'
import type { CollectionAfterLogoutHook, PayloadRequest } from 'payload'
import {
  expireSessionCookies,
  presentsSessionCredential,
  revokePresentedSessions,
} from './endpoints.js'
import type { WiredOptions } from './options.js'
import { REQUEST_VERIFY_KEY } from './session.js'

/**
 * The registered provider behind one registry id, or `null`. The
 * request's memo carries the provider id as data (typed `unknown`), so
 * the registry id — the branded key `require` needs — is re-resolved by
 * comparison, like `suspendRevokeHook`.
 */
function registeredProvider(wired: WiredOptions, id: string): IdentityProviderPort | null {
  for (const candidate of wired.registry.ids()) {
    if (candidate !== id) {
      continue
    }
    const required = wired.registry.require(candidate)
    return required.isOk() ? required.value : null
  }
  return null
}

/**
 * The provider session this request's own authentication already
 * resolved — WITHOUT walking any provider again. The auth strategy
 * stores the settled Result on `req.context` (issue #42 memo) and the
 * endpoint readers store the pending ResultAsync; either carries the
 * verified session (`authLinkMeHook` reads the same memo). `null` when
 * nothing was resolved: local strategies only, or verification refused.
 */
async function memoizedSession(
  wired: WiredOptions,
  req: PayloadRequest
): Promise<{ readonly provider: IdentityProviderPort; readonly sessionId: string } | null> {
  const memo: unknown = isRecord(req.context) ? req.context[REQUEST_VERIFY_KEY] : undefined
  if (memo === undefined) {
    return null
  }
  const settled: unknown = memo instanceof ResultAsync ? await memo : memo
  if (!(settled instanceof Ok) || !isRecord(settled.value)) {
    return null
  }
  const { id, providerId } = settled.value
  if (typeof id !== 'string' || id === '' || typeof providerId !== 'string') {
    return null
  }
  const provider = registeredProvider(wired, providerId)
  return provider === null ? null : { provider, sessionId: id }
}

/**
 * GHSA-gw3c-8g59-q72j: Payload's admin **Log out** (and any
 * `POST /api/<users>/logout`) ends only Payload's own token — the
 * provider's session cookie stayed live, so the next request to
 * /admin or REST was still authenticated as the same user. This
 * afterLogout hook closes that gap:
 *
 * - the session the plugin already verified for this request (the
 *   per-request memo — no second provider walk) is revoked through the
 *   provider port;
 * - when nothing was verified but the request still PRESENTS a
 *   provider credential (an expired or refused session, or a mixed
 *   local+provider login), whatever is still live is swept, like the
 *   `DELETE /auth-link/session` endpoint's idempotent path;
 * - every registered provider's session (and non-session logout,
 *   legacy, and per-request multi-session) cookies are expired on the
 *   response — `req.responseHeaders`, which Payload merges onto the
 *   REST logout response.
 *
 * A Payload-local-only logout presents no provider credential and is
 * left untouched. Everything is best-effort and fail-safe: a provider
 * error is logged (never thrown) and must not break the logout
 * response — Payload has already ended its own session by the time
 * this runs.
 */
export function providerSessionLogoutHook(wired: WiredOptions): CollectionAfterLogoutHook {
  return async ({ req }) => {
    try {
      const memoized = await memoizedSession(wired, req)
      if (memoized !== null) {
        const revoked = await memoized.provider.revokeSession(memoized.sessionId)
        if (revoked.isErr()) {
          wired.logger.warn('admin logout: provider session revoke failed', {
            providerId: memoized.provider.id,
            cause: revoked.error.cause ?? revoked.error,
          })
        } else {
          wired.logger.info('admin logout: provider session revoked', {
            providerId: memoized.provider.id,
          })
        }
      } else if (presentsSessionCredential(wired, req.headers)) {
        // A provider credential the strategy could not verify: sweep
        // whatever is still live on every registered provider. No
        // verified session to name here, so none is skipped.
        await revokePresentedSessions(wired, req.headers, null)
      } else {
        // Payload-local-only logout: nothing provider-side to end, no
        // provider cookies presented, no writes on the response.
        return
      }
      const responseHeaders = req.responseHeaders ?? (req.responseHeaders = new Headers())
      expireSessionCookies(wired, responseHeaders, req.headers)
    } catch (error) {
      wired.logger.warn('admin logout: provider cleanup failed; logout response unchanged', {
        cause: error instanceof Error ? error.message : String(error),
      })
    }
  }
}
