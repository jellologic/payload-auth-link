import {
  assertSupportedVersion,
  consoleLogger,
  InvalidConfigError,
  isSilentLogger,
  readInstalledVersion,
  type VersionRange,
} from '@payload-auth-link/core'
import type { CollectionConfig, Config, GlobalConfig, Plugin } from 'payload'
import {
  composeAuditLogger,
  withImpersonationAuditCollections,
  withImpersonationAuditGlobals,
} from './audit.js'
import {
  applyUsersCollection,
  accountControlsGateHook,
  accountControlsGlobalGateHook,
} from './collections.js'
import { createEndpoints } from './endpoints.js'
import { subscribeIdentityEvents } from './lifecycle.js'
import { applyOrganizationCollections, createOrganizationEndpoints } from './organizations.js'
import { wireOptions, type AuthLinkPluginOptions, type WiredOptions } from './options.js'
import { auditStoredRoles } from './role-audit.js'
import { createAuthLinkStrategy, strategyName } from './strategy.js'
import { registerAuthLinkServer } from './server.js'

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
 * Request-time account controls (GHSA-f4hj) on every collection the
 * users assembly does not already cover: a suspended user's local JWT
 * or API key is refused on the next request, and `requireMfaForRoles`
 * roles are withheld from local sessions before any access check
 * reads them. Without this, a host collection with permissive access
 * would stay a suspended session's fallback surface. The users
 * collection carries the same hook from its own assembly and is
 * skipped here.
 */
function withAccountControls(
  collections: readonly CollectionConfig[] | undefined,
  wired: WiredOptions
): CollectionConfig[] {
  const gate = accountControlsGateHook(wired)
  const usersSlug = wired.config.map.usersCollection
  return (collections ?? []).map((collection) =>
    collection.slug === usersSlug
      ? collection
      : {
          ...collection,
          hooks: {
            ...collection.hooks,
            beforeOperation: [...(collection.hooks?.beforeOperation ?? []), gate],
          },
        }
  )
}

/**
 * The same controls for globals: a suspended session must not read or
 * write global data either.
 */
function withAccountControlsGlobals(
  globals: readonly GlobalConfig[] | undefined,
  wired: WiredOptions
): GlobalConfig[] {
  const gate = accountControlsGlobalGateHook(wired)
  return (globals ?? []).map((global) => ({
    ...global,
    hooks: {
      ...global.hooks,
      beforeOperation: [...(global.hooks?.beforeOperation ?? []), gate],
    },
  }))
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
  // CAP-8b audit: every audit event goes to the logger and, when
  // configured, the durable `onAudit` sink — "audited" must survive
  // log rotation, so the sink is not a logger nicety.
  const auditLogger =
    wired.onAudit === null ? wired.logger : composeAuditLogger(wired.logger, wired.onAudit)
  const plugin: Plugin = (config: Config) => {
    // #55/#72: the provider-backed admin login view. Registered as a
    // custom view; the import map must include
    // `@payload-auth-link/plugin/admin#ProviderLoginView` — hence the
    // explicit `exportName` (a bare `path` would resolve to the
    // module's non-existent default export). The doctor checks for it.
    // The view's provider form posts to a cookie-transport provider's
    // sign-in endpoint, so registering it without one would ship a
    // form that always 404s — refuse the combination at config time.
    if (
      wired.adminProviderLoginView &&
      ![...wired.registry.ids()].some((id) => {
        const required = wired.registry.require(id)
        return required.isOk() && required.value.sessionCookie !== undefined
      })
    ) {
      throw new InvalidConfigError(
        `admin.loginView: 'provider' renders the cookie-transport provider's sign-in form (${wired.adminAuthBase}/sign-in/email) — register a provider that mints cookie sessions (better-auth), or keep the default login view`
      )
    }
    const apiRoute = config.routes?.api ?? '/api'
    const adminConfig = wired.adminProviderLoginView
      ? {
          ...config.admin,
          components: {
            ...config.admin?.components,
            views: {
              ...config.admin?.components?.views,
              login: {
                Component: {
                  path: '@payload-auth-link/plugin/admin',
                  exportName: 'ProviderLoginView',
                  // Derived from the Payload config (custom `routes`,
                  // users slug) and plugin options, never hard-coded.
                  clientProps: {
                    authBase: wired.adminAuthBase,
                    loginEndpoint: `${apiRoute}/${wired.config.map.usersCollection}/login`,
                    adminRoute: config.routes?.admin ?? '/admin',
                    signInPath: wired.adminSignInPath,
                  },
                },
              },
            },
          },
        }
      : config.admin
    return {
      ...config,
      // Impersonation audit (CAP-8b): every collection/global gains a
      // `beforeOperation` hook that logs operations performed while an
      // operator impersonates the request's user (see `audit.ts`).
      collections: withImpersonationAuditCollections(
        withAccountControls(
          applyOrganizationCollections(
            applyUsersCollection(config.collections, wired, strategy),
            wired
          ),
          wired
        ),
        auditLogger
      ),
      globals: withAccountControlsGlobals(
        withImpersonationAuditGlobals(config.globals, auditLogger),
        wired
      ),
      ...(adminConfig === undefined ? {} : { admin: adminConfig }),
      endpoints: [
        ...(config.endpoints ?? []),
        ...createEndpoints(wired),
        ...createOrganizationEndpoints(wired),
      ],
      // CAP-14: subscribe provider identity lifecycle events once the
      // Payload instance exists, then run the builder's own onInit.
      onInit: async (payload) => {
        // #54: register the server API for `authLinkServer(payload)`.
        registerAuthLinkServer(payload, wired)
        // "Audited" must land somewhere: with an impersonation-capable
        // provider and neither a hearing logger nor an audit sink, say
        // so once, through a channel the builder has not muted.
        const impersonationCapable = wired.registry.ids().some((id) => {
          const required = wired.registry.require(id)
          return required.isOk() && required.value.capabilities.has('impersonation')
        })
        if (impersonationCapable && wired.onAudit === null && isSilentLogger(wired.logger)) {
          consoleLogger().warn(
            'payload-auth-link: an impersonation-capable provider is configured, but the ' +
              'logger is silent and no onAudit sink is set — impersonation audit events ' +
              'will be dropped. Pass onAudit or a logger.'
          )
        }
        // B11: one startup warning when stored roles drifted out of the
        // configured set (removed/renamed role). Never blocks the boot.
        await auditStoredRoles(wired, payload)
        subscribeIdentityEvents(wired, payload)
        await config.onInit?.(payload)
      },
    }
  }
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
export { createBetterAuthCompatShim, type BetterAuthCompatShim } from './compat-shim.js'
export {
  authLinkServer,
  registerAuthLinkServer,
  AuthLinkServerMissingError,
  ServerSessionsDisabledError,
  ServerSessionUnsupportedError,
  UserSuspendedError,
  type AuthLinkServer,
  type CreateSessionForOptions,
} from './server.js'
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
