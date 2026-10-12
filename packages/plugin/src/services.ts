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
  })
  const sessions = createSessionService({
    users,
    registry: wired.registry,
    logger: wired.logger,
    clock: wired.clock,
    defaultRoles: [wired.config.defaultRole],
  })
  return { users, sessions }
}
