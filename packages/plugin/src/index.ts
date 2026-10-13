import type { Config, Plugin } from 'payload'
import { withImpersonationAuditCollections, withImpersonationAuditGlobals } from './audit.js'
import { applyUsersCollection } from './collections.js'
import { createEndpoints } from './endpoints.js'
import { subscribeIdentityEvents } from './lifecycle.js'
import { applyOrganizationCollections, createOrganizationEndpoints } from './organizations.js'
import { wireOptions, type AuthLinkPluginOptions } from './options.js'
import { createAuthLinkStrategy, strategyName } from './strategy.js'

/** Plugin slug registered with Payload. */
export const pluginSlug = 'payload-auth-link'

/**
 * Payload plugin wiring external identity providers to Payload users.
 * Appends the users collection (or extends the existing one), registers the
 * auth strategy, mounts session endpoints, and validates everything
 * fail-fast at config time.
 *
 * Deliberately NOT built on `definePlugin`: v3 spreads options into the
 * plugin args while v4 nests them under `options`, so any
 * `definePlugin`-based entry reads garbage on one line. A plain `Plugin`
 * function (identical shape on v3 and v4) keeps one entrypoint for both.
 * Invalid options throw here, at factory call time — still config time
 * from the builder's perspective, and earlier than plugin application.
 */
export function authLink(options: AuthLinkPluginOptions): Plugin {
  const wired = wireOptions(options)
  const strategy = createAuthLinkStrategy(wired)
  const plugin: Plugin = (config: Config) => ({
    ...config,
    // Impersonation audit (CAP-8b): every collection/global gains a
    // `beforeOperation` hook that logs operations performed while an
    // operator impersonates the request's user (see `audit.ts`).
    collections: withImpersonationAuditCollections(
      applyOrganizationCollections(
        applyUsersCollection(config.collections, wired, strategy),
        wired
      ),
      wired.logger
    ),
    globals: withImpersonationAuditGlobals(config.globals, wired.logger),
    endpoints: [
      ...(config.endpoints ?? []),
      ...createEndpoints(wired),
      ...createOrganizationEndpoints(wired),
    ],
    // CAP-14: subscribe provider identity lifecycle events once the
    // Payload instance exists, then run the builder's own onInit.
    onInit: async (payload) => {
      subscribeIdentityEvents(wired, payload)
      await config.onInit?.(payload)
    },
  })
  plugin.slug = pluginSlug
  // Cross-plugin discovery parity with `definePlugin` (which exposes the
  // raw options on the function). Mutating this has no effect: wiring is
  // eager and already captured above.
  plugin.options = { ...options }
  return plugin
}

export type { AuthLinkPluginOptions }
export type { UserGovernanceFields, WiredOptions, WiredOrganizations } from './options.js'
export { strategyName }
export {
  defaultDeniedWhileImpersonating,
  denyWhileImpersonating,
  denyWithoutMfa,
  impersonationActorFromRequest,
  impersonationStateFromRequest,
  isImpersonating,
  sessionMfaSatisfied,
} from './access.js'
export type {
  DenyWhileImpersonatingAccess,
  ImpersonationOperation,
  ImpersonationState,
} from './access.js'
export { getOrgMembership, orgManagerRoles, requireOrgRole } from './organizations.js'
