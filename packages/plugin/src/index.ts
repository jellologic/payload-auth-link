import {
  assertSupportedVersion,
  readInstalledVersion,
  type VersionRange,
} from '@payload-auth-link/core'
import type { Config, Plugin } from 'payload'
import { withImpersonationAuditCollections, withImpersonationAuditGlobals } from './audit.js'
import { applyUsersCollection } from './collections.js'
import { createEndpoints } from './endpoints.js'
import { subscribeIdentityEvents } from './lifecycle.js'
import { applyOrganizationCollections, createOrganizationEndpoints } from './organizations.js'
import { wireOptions, type AuthLinkPluginOptions } from './options.js'
import { auditStoredRoles } from './role-audit.js'
import { createAuthLinkStrategy, strategyName } from './strategy.js'

/** Plugin slug registered with Payload. */
export const pluginSlug = 'payload-auth-link'

/**
 * Payload versions this release validated (Phase-1 bisect): the
 * named-plugin (`slug`/`options`) and global-hook APIs the plugin
 * uses land in 3.83.0; 4.0.0-beta.0 is the exact tested v4 build.
 * Widened only by the compatibility matrix, never by optimism.
 */
export const supportedPayloadBand: readonly VersionRange[] = [
  { min: '3.83.0', maxExclusive: '4.0.0' },
  { exact: '4.0.0-beta.0' },
]

function readPayloadVersion(): string | null {
  return readInstalledVersion('payload', import.meta.url)
}

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
  // Fail at wiring time on an unvalidated Payload version, before any
  // collection write (B4). Unreadable manifests (exotic bundling) warn
  // once instead of guessing.
  const payloadVersion = readPayloadVersion()
  if (payloadVersion === null) {
    wired.logger.warn(
      'payload-auth-link: could not read the installed payload version; skipping the supported-version assertion'
    )
  } else {
    assertSupportedVersion('payload', payloadVersion, supportedPayloadBand)
  }
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
      // B11: one startup warning when stored roles drifted out of the
      // configured set (removed/renamed role). Never blocks the boot.
      await auditStoredRoles(wired, payload)
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
