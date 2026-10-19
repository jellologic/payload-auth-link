import { isRecord } from '@payload-auth-link/core'
import type { AuthStrategy } from 'payload'
import { REQUEST_VERIFY_KEY } from './session.js'
import { logVerifyFailure } from './access.js'
import { toPayloadUser } from './mapping.js'
import { createServices } from './services.js'
import { armLocalCredentialGate, disarmLocalCredentialGate } from './credential-gate.js'
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
  const authenticateSession = authenticateProviderSession(wired)
  return {
    name: strategyName,
    authenticate: async (args) => {
      const { headers, payload, req } = args as StrategyArgs
      const result = await authenticateSession({ headers, payload, req })
      // GHSA-mjvh: with no provider session, Payload goes on to its own
      // API-key and local-JWT strategies. Arm the account-control veto
      // for the credential they will read (see `credential-gate.ts`).
      if (result.user === null) {
        armLocalCredentialGate(headers, payload, req, wired)
      } else {
        disarmLocalCredentialGate(req)
      }
      return result
    },
  }
}

type StrategyArgs = {
  headers: Headers
  payload: import('payload').Payload
  req?: import('payload').PayloadRequest | undefined
}

type StrategyResult = Awaited<ReturnType<AuthStrategy['authenticate']>>

function authenticateProviderSession(
  wired: WiredOptions
): (args: StrategyArgs) => Promise<StrategyResult> {
  return async ({ headers, payload, req }) => {
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
    // governance compares canonical roles everywhere else. A role with
    // no stored form is dropped, never passed through raw: `wireOptions`
    // makes the map total over the configured roles and reads drop
    // unconfigured ones, so a miss means a hand-built or drifted wiring
    // — and an unknown value on `req.user.roles` must not grant.
    const roles =
      wired.projectRolesAs === 'stored'
        ? payloadUser.roles.flatMap((role) => {
            const stored = wired.roleValues[role]
            if (stored === undefined) {
              wired.logger.warn('strategy dropped a role with no stored value', { role })
              return []
            }
            return [stored]
          })
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
        if (payloadUser.anonymous === true) {
          user.anonymous = true
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
  }
}
