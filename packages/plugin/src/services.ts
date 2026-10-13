import { okAsync, ResultAsync } from 'neverthrow'
import {
  emailDomainAllowed,
  emailDomainOf,
  RepositoryError,
  type Email,
  type ProviderId,
} from '@payload-auth-link/core'
import type { Payload } from 'payload'
import type { WiredOptions } from './options.js'
import { createPayloadUserRepository } from './repository.js'
import { createSessionService } from './session.js'

/**
 * Single wiring change point for request-scoped services: the strategy
 * and the endpoints both build their repository + session service here,
 * per call, so role changes apply to the very next request.
 */
export function createServices(wired: WiredOptions, payload: Payload) {
  const users = createPayloadUserRepository({
    payload,
    map: wired.config.map,
    defaultRole: wired.config.defaultRole,
    logger: wired.logger,
    clock: wired.clock,
    ids: wired.ids,
    depth: wired.depth,
    userFields: wired.userFields,
    // B11: reads drop stored roles outside the configured set, so a
    // removed role stops granting at the next session, not after an
    // unrelated user-doc write.
    configuredRoles: new Set(wired.config.roles),
  })
  const orgs = wired.organizations
  const sessions = createSessionService({
    users,
    registry: wired.registry,
    logger: wired.logger,
    clock: wired.clock,
    defaultRoles: [wired.config.defaultRole],
    linkingPolicy: wired.linkingPolicy,
    admitChannels: wired.admitChannels,
    // CAP-15: only wired when SSO providers are registered. The
    // checker resolves the email domain against every Payload
    // organization's verified domains, live per request.
    ...(orgs === null || orgs.ssoProviders.length === 0
      ? {}
      : {
          ssoDomainAllowed: (providerId: ProviderId, email: Email | null) => {
            if (!orgs.ssoProviders.includes(providerId)) {
              return okAsync(true)
            }
            if (email === null) {
              return okAsync(false)
            }
            const domain = emailDomainOf(email)
            return ResultAsync.fromPromise(
              payload.find({
                collection: orgs.organizationsCollection,
                where: { 'verifiedDomains.domain': { equals: domain } },
                limit: 1,
                depth: 0,
                overrideAccess: true,
              }),
              (cause) => new RepositoryError('ssoDomainAllowed', { cause })
            ).map((result) => result.docs.length > 0 && emailDomainAllowed(email, [domain]))
          },
        }),
  })
  return { users, sessions }
}
