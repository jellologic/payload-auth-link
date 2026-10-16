import { isRecord } from '@payload-auth-link/core'
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
      // `req.user.id` carries the database's own id type: Payload v4
      // writes it into `createdBy`/`updatedBy` relationships, which
      // reject a string id on number-id adapters (SQLite, Postgres).
      const nativeId: string | number =
        payload.db.defaultIDType === 'number' && /^\d+$/.test(payloadUser.id)
          ? Number(payloadUser.id)
          : payloadUser.id
      // Issue #57: `reqUser: 'document'` loads the full user document
      // (once per request, through the same `req.context` memo the
      // endpoint handlers share) so access functions reading other
      // fields keep working unchanged. The security-relevant projected
      // fields stay authoritative on top of it.
      if (wired.reqUser === 'document') {
        const memo =
          req !== undefined && isRecord(req.context)
            ? (req.context as Record<string, unknown>)
            : undefined
        const memoKey = 'payloadAuthLink:reqUserDocument'
        let document: unknown = memo?.[memoKey]
        if (document === undefined) {
          document = await payload.findByID({
            collection: wired.config.map.usersCollection,
            id: found.value.id,
            depth: wired.depth,
            overrideAccess: true,
          })
          if (memo !== undefined) {
            memo[memoKey] = document
          }
        }
        if (isRecord(document)) {
          // The document's own fields ride under an index signature;
          // the security-relevant projected fields are written on top
          // and typed exactly.
          const user: Record<string, unknown> & {
            id: string | number
            email: string
            collection: string
            _strategy: string
          } = {
            ...document,
            id: nativeId,
            email: payloadUser.email,
            roles,
            collection: wired.config.map.usersCollection,
            _strategy: strategyName,
          }
          if (payloadUser.mfaRequired !== undefined) {
            user.mfaRequired = payloadUser.mfaRequired
          }
          if (payloadUser.assurance !== undefined) {
            user.assurance = payloadUser.assurance
          }
          if (payloadUser.actor !== undefined) {
            user.actor = payloadUser.actor
          }
          if (payloadUser.organizationId !== undefined) {
            user.organizationId = payloadUser.organizationId
          }
          return { user }
        }
      }
      return {
        user: {
          ...payloadUser,
          id: nativeId,
          roles,
          _strategy: strategyName,
        },
      }
    },
  }
}
