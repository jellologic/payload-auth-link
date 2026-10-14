import type { AuthStrategy } from 'payload'
import { REQUEST_VERIFY_KEY } from './session.js'
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
    authenticate: async (args) => {
      const { headers, payload, req } = args as {
        headers: Headers
        payload: import('payload').Payload
        req?: import('payload').PayloadRequest
      }
      const { users, sessions } = createServices(wired, payload)
      const verified = await sessions.verify(headers, req)
      // Share the resolution with the endpoint handler (issue #42):
      // the strategy's `req` is the same object the endpoint sees, and
      // `req.context` survives across bundler graphs where module
      // instances do not.
      if (req !== undefined && req.context !== undefined) {
        ;(req.context as Record<string, unknown>)[REQUEST_VERIFY_KEY] = verified
      }
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
      const payloadUser = toPayloadUser(
        found.value,
        wired.config.map.usersCollection,
        verified.value,
        {
          requireMfaForRoles: wired.requireMfaForRoles,
        }
      )
      // Issue #56: `projectRolesAs: 'stored'` hands access functions
      // the values the database stores. The MFA gate above already ran
      // on canonical roles — projection is output-shaping only, and
      // governance compares canonical roles everywhere else.
      const roles =
        wired.projectRolesAs === 'stored'
          ? payloadUser.roles.map((role) => wired.roleValues[role] ?? role)
          : payloadUser.roles
      return {
        user: {
          ...payloadUser,
          roles,
          _strategy: strategyName,
        },
      }
    },
  }
}
