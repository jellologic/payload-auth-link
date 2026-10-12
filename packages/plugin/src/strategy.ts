import type { AuthStrategy } from 'payload'
import { logVerifyFailure } from './access.js'
import { toPayloadUser } from './mapping.js'
import { createServices } from './services.js'
import type { WiredOptions } from './options.js'

/** Auth strategy name registered on the users collection. */
export const strategyName = 'auth-link'

/**
 * Custom auth strategy delegating to the `SessionPort`. Read-only: it never
 * refreshes provider state (no login loops by construction).
 *
 * The strategy interface has no error channel, so every failure mode —
 * expired, invalid, unlinked, or storage outage — resolves to
 * `{ user: null }` with a loud log. The user document is reloaded fresh on
 * each call so role changes apply to the very next request.
 */
export function createAuthLinkStrategy(wired: WiredOptions): AuthStrategy {
  return {
    name: strategyName,
    authenticate: async ({ headers, payload }) => {
      const { users, sessions } = createServices(wired, payload)
      const verified = await sessions.verify(headers)
      if (verified.isErr()) {
        logVerifyFailure(wired.logger, 'strategy', verified.error)
        return { user: null }
      }
      const found = await users.findById(verified.value.userId)
      if (found.isErr()) {
        wired.logger.error('strategy user reload failed', {
          cause: found.error.cause ?? found.error,
        })
        return { user: null }
      }
      if (!found.value) {
        wired.logger.warn('strategy session has no user document')
        return { user: null }
      }
      return {
        user: {
          ...toPayloadUser(found.value, wired.config.map.usersCollection),
          _strategy: strategyName,
        },
      }
    },
  }
}
