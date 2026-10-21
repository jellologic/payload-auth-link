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
import { withMigrationRecords } from './migration-records.js'
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
    // #55/#72/#121: the provider-backed admin views (login, forgot,
    // reset). Registered as custom views; the import map must include
    // the `@payload-auth-link/plugin/admin#Provider…View` exports —
    // hence the explicit `exportName` (a bare `path` would resolve to
    // the module's non-existent default export). The doctor checks for
    // the login one. The provider forms post to a cookie-transport
    // provider's endpoints, so registering them without one would ship
    // forms that always 404 — refuse the combination at config time.
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
    // Issue #126: guests resolve to their own document only where the
    // engine wrote it — adopt mode with the user model adopted. The
    // provider port's fact is the wiring proof; anything else refuses
    // at config time instead of refusing (or mis-linking) at runtime.
    if (
      wired.admitAnonymous &&
      ![...wired.registry.ids()].some((id) => {
        const required = wired.registry.require(id)
        return required.isOk() && required.value.providerUserIdsAreDocumentIds === true
      })
    ) {
      throw new InvalidConfigError(
        "admitAnonymous: true resolves a guest session to its own document, which only exists where the engine writes user rows into the mapped users collection — run the better-auth engine with schemaMap.user and idStrategy: 'payload' (adopt mode), or drop the option"
      )
    }
    const apiRoute = config.routes?.api ?? '/api'
    const adminRoute = config.routes?.admin ?? '/admin'
    // #121: the provider reset view's route — Payload's `routes.admin`
    // joined with `admin.routes.reset` (defaults '/admin' + '/reset').
    // The keyed registration below follows a customized
    // `admin.routes.reset` automatically; the forgot view points the
    // reset email's `redirectTo` at this same path.
    const resetRoute = `${adminRoute.endsWith('/') ? adminRoute.slice(0, -1) : adminRoute}${
      config.admin?.routes?.reset ?? '/reset'
    }`
    // Issue #157: the login view's alternative methods (magic link,
    // social sign-in) render only when the provider's engine actually
    // supports them. The port's facts are read the same way the gates
    // above read theirs — never a separate app-side list. The flags
    // merge across registered providers (normally exactly one
    // cookie-transport one); social ids dedupe in first-seen order.
    let loginMagicLink = false
    const loginSocialProviders: string[] = []
    for (const id of wired.registry.ids()) {
      const required = wired.registry.require(id)
      if (!required.isOk()) {
        continue
      }
      const port = required.value
      if (port.magicLinkEnabled === true) {
        loginMagicLink = true
      }
      for (const providerId of port.socialProviders ?? []) {
        if (!loginSocialProviders.includes(providerId)) {
          loginSocialProviders.push(providerId)
        }
      }
    }
    // The import map entry every provider view shares: one module,
    // named exports (a bare `path` would resolve to the module's
    // non-existent default export).
    const providerView = (exportName: string, clientProps: Record<string, unknown>) => ({
      Component: {
        path: '@payload-auth-link/plugin/admin',
        exportName,
        clientProps,
      },
    })
    const adminConfig = wired.adminProviderLoginView
      ? {
          ...config.admin,
          components: {
            ...config.admin?.components,
            views: {
              ...config.admin?.components?.views,
              login: providerView('ProviderLoginView', {
                authBase: wired.adminAuthBase,
                loginEndpoint: `${apiRoute}/${wired.config.map.usersCollection}/login`,
                adminRoute,
                signInPath: wired.adminSignInPath,
                // Issue #157: the alternative methods, derived from the
                // provider port — absent facts render no new section.
                magicLink: loginMagicLink,
                socialProviders: loginSocialProviders,
              }),
              // #121: the provider forgot/reset views. The `forgot`
              // view replaces Payload's built-in /admin/forgot screen;
              // the `reset` view serves /admin/reset (Better Auth's
              // email link lands there with `?token=`). The keyed
              // entries ride `admin.routes.forgot`/`admin.routes.reset`,
              // so a customized route path keeps working.
              forgot: providerView('ProviderForgotPasswordView', {
                authBase: wired.adminAuthBase,
                forgotEndpoint: `${apiRoute}/${wired.config.map.usersCollection}/forgot-password`,
                adminRoute,
                resetRoute,
              }),
              reset: providerView('ProviderResetPasswordView', {
                authBase: wired.adminAuthBase,
                resetEndpoint: `${apiRoute}/${wired.config.map.usersCollection}/reset-password`,
                adminRoute,
              }),
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
          withMigrationRecords(
            applyOrganizationCollections(
              applyUsersCollection(config.collections, wired, strategy),
              wired
            ),
            (detail) => {
              throw new InvalidConfigError(detail)
            }
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
