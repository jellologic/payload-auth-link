import {
  isSuspendedAt,
  type ApiKeyVerification,
  type Capability,
  type IdentityProviderPort,
  type UserId,
} from '@payload-auth-link/core'

/** Accept number or string ids from app code; the brand is compile-time only. */
function asUserId(userId: number | string): UserId {
  return String(userId) as UserId
}
import type { Payload } from 'payload'
import { composeAuditLogger } from './audit.js'
import { toPayloadUser } from './mapping.js'
import type { WiredOptions } from './options.js'
import { createServices } from './services.js'
import { strategyName } from './strategy.js'

/**
 * The supported server-side session API (issue #54): everything apps
 * used to reach Better Auth internals for — minting a session,
 * listing and revoking, verifying an API key, signing the session
 * cookie — behind one typed surface that goes through the same gates
 * as every other session: suspension refusal, the MFA projection,
 * role governance, and the audit sink.
 *
 * Obtain the instance from `authLinkServer(payload)` after the plugin
 * is installed on that Payload instance. Server session creation is
 * additionally gated by `allowServerSessions` (default `'dev-only'`):
 * refused with {@link ServerSessionsDisabledError} when disabled, or
 * when `'dev-only'` and `NODE_ENV` is anything but `'development'`.
 */

/** Thrown by `authLinkServer(payload)` when the plugin is not installed there. */
export class AuthLinkServerMissingError extends Error {
  constructor() {
    super(
      'authLinkServer: no payload-auth-link plugin is installed on this Payload instance; ' +
        'add authLink(options) to the config and pass the same instance'
    )
    this.name = 'AuthLinkServerMissingError'
  }
}

/** Thrown by `createSessionFor` when server session creation is disabled. */
export class ServerSessionsDisabledError extends Error {
  constructor(mode: 'dev-only' | true | false) {
    super(
      mode === false
        ? 'createSessionFor: server sessions are disabled (allowServerSessions: false)'
        : "createSessionFor: server sessions are dev-only and this is a production runtime (allowServerSessions: 'dev-only'); set allowServerSessions: true to enable"
    )
    this.name = 'ServerSessionsDisabledError'
  }
}

/** Thrown when no linked identity of the user supports the needed capability. */
export class ServerSessionUnsupportedError extends Error {
  constructor(userId: string, capability: Capability) {
    super(`user ${userId} has no linked identity whose provider supports ${capability}`)
    this.name = 'ServerSessionUnsupportedError'
  }
}

/** Thrown when the user is suspended (CAP-7): the same gate the strategies apply. */
export class UserSuspendedError extends Error {
  readonly suspendedUntil: Date
  constructor(suspendedUntil: Date) {
    super('createSessionFor: user is suspended')
    this.name = 'UserSuspendedError'
    this.suspendedUntil = suspendedUntil
  }
}

/**
 * Wiring registered by the plugin's `onInit`; `authLinkServer` reads it.
 * A WeakMap (not an instance property): DNA bans monkey-patching the
 * Payload instance, and the entry dies with the instance.
 *
 * One map per PROCESS, not per module copy: bundlers can load this
 * module more than once (TanStack Start's admin and API route graphs
 * do) while sharing one cached Payload, so a per-module map registered
 * by the copy that booted Payload is invisible to the other copy. The
 * map lives in a `Symbol.for` slot on `globalThis`, shared by every
 * copy.
 */
const serverRegistryKey = Symbol.for('@payload-auth-link/plugin/server-registry')

function processRegistry(): WeakMap<Payload, WiredOptions> {
  const slots = globalThis as { [serverRegistryKey]?: WeakMap<Payload, WiredOptions> }
  const existing = slots[serverRegistryKey]
  if (existing !== undefined) {
    return existing
  }
  const created = new WeakMap<Payload, WiredOptions>()
  slots[serverRegistryKey] = created
  return created
}

const serverRegistry = processRegistry()

/** Called from the plugin's `onInit`. Not public API. */
export function registerAuthLinkServer(payload: Payload, wired: WiredOptions): void {
  serverRegistry.set(payload, wired)
}

/** Options for {@link AuthLinkServer.createSessionFor}. */
export type CreateSessionForOptions = {
  /**
   * Why the session was minted — required; lands in the audit event
   * (`dev-auto-login`, `api-key bridge`, `support session`, …).
   */
  readonly reason: string
  /** Session lifetime in seconds. Omitted = the provider's default. */
  readonly ttlSeconds?: number | undefined
  /** Who asked for the session; recorded in the audit event. */
  readonly actor?: string | undefined
  /**
   * A server-vouched step-up proof: set ONLY when the server has
   * itself verified a second factor for this mint (there is no
   * client input to trust here). The default records the session as
   * carrying NO MFA proof — a mint ran no challenge — so MFA-gated
   * roles stay withheld until a proof is recorded.
   */
  readonly mfaProof?: boolean | undefined
}

/** The supported server-side session API (issue #54). */
export type AuthLinkServer = {
  /**
   * Resolve the Payload user behind a request's session — the same
   * rules the strategies apply: suspension refusal, MFA projection,
   * stored-role projection, impersonation facts. Returns `null` when
   * the request carries no (live) session.
   */
  readonly getSession: (headers: Headers) => Promise<Record<string, unknown> | null>
  /**
   * Mint a session for one Payload user. Refused for suspended users;
   * audited with `reason` and `actor`. Returns the session token, its
   * expiry, and — when the provider's session transport is a cookie —
   * the correctly signed `Set-Cookie` value for it.
   */
  readonly createSessionFor: (
    userId: number | string,
    options: CreateSessionForOptions
  ) => Promise<{
    readonly sessionId: string
    readonly token: string
    readonly expiresAt: Date
    readonly setCookie: string | undefined
  }>
  /** One user's live sessions, as the provider reports them. */
  readonly listSessions: (
    userId: number | string
  ) => Promise<readonly { readonly sessionId: string; readonly expiresAt: Date | null }[]>
  /** Revoke one session by its provider-verified handle. */
  readonly revokeSession: (sessionId: string) => Promise<void>
  /** Revoke every live session of one Payload user. */
  readonly revokeAllForUser: (userId: number | string) => Promise<void>
  /** Verify an API key; `null` when the key is unknown. */
  readonly verifyApiKey: (key: string) => Promise<ApiKeyVerification | null>
  /**
   * The provider's signed session cookie for one session token
   * (`token.<signature>` — Better Auth only accepts the signed form).
   * Async: the provider resolves its engine's secret on first use.
   */
  readonly sessionCookie: (token: string) => Promise<string>
}

/**
 * Resolve the server API for a Payload instance the plugin is
 * installed on (issue #54). Throws
 * {@link AuthLinkServerMissingError} when the plugin is not part of
 * that instance's config.
 */
export function authLinkServer(payload: Payload): AuthLinkServer {
  const wired = serverRegistry.get(payload)
  if (wired === undefined) {
    throw new AuthLinkServerMissingError()
  }
  return buildAuthLinkServer(wired, payload)
}

function serverSessionsEnabled(wired: WiredOptions): boolean {
  if (wired.allowServerSessions === true) {
    return true
  }
  if (wired.allowServerSessions === false) {
    return false
  }
  // 'dev-only': ONLY an explicit development runtime. Anything else —
  // production, test, staging, unset — refuses: a gate that fails open
  // on every runtime that merely isn't 'production' (CI, test, a
  // staging deploy) was a gate in name only.
  return process.env.NODE_ENV === 'development'
}

/** The first registered provider carrying a capability, if any. */
function firstProviderWith(
  wired: WiredOptions,
  capability: Capability
): IdentityProviderPort | undefined {
  for (const id of wired.registry.ids()) {
    const required = wired.registry.require(id)
    if (required.isErr()) {
      continue
    }
    if (required.value.capabilities.has(capability)) {
      return required.value
    }
  }
  return undefined
}

/** Every registered provider carrying a capability, in registry order. */
function allProvidersWith(wired: WiredOptions, capability: Capability): IdentityProviderPort[] {
  const providers: IdentityProviderPort[] = []
  for (const id of wired.registry.ids()) {
    const required = wired.registry.require(id)
    if (required.isErr()) {
      continue
    }
    if (required.value.capabilities.has(capability)) {
      providers.push(required.value)
    }
  }
  return providers
}

function buildAuthLinkServer(wired: WiredOptions, payload: Payload): AuthLinkServer {
  const auditLog = composeAuditLogger(wired.logger, wired.onAudit ?? (() => {}))
  return {
    async getSession(headers) {
      const { sessions, users } = createServices(wired, payload)
      const verified = await sessions.verify(headers)
      if (verified.isErr() || !verified.value) {
        return null
      }
      const found = await users.findById(verified.value.userId)
      if (found.isErr() || !found.value) {
        return null
      }
      const record = found.value
      const payloadUser = toPayloadUser(record, wired.config.map.usersCollection, verified.value, {
        requireMfaForRoles: wired.requireMfaForRoles,
      })
      const roles =
        wired.projectRolesAs === 'stored'
          ? payloadUser.roles.map((role) => wired.roleValues[role] ?? role)
          : payloadUser.roles
      return {
        ...payloadUser,
        roles,
        collection: wired.config.map.usersCollection,
        _strategy: strategyName,
      }
    },

    async createSessionFor(userId, options) {
      if (!serverSessionsEnabled(wired)) {
        throw new ServerSessionsDisabledError(wired.allowServerSessions)
      }
      const { users } = createServices(wired, payload)
      const found = await users.findById(asUserId(userId))
      if (found.isErr() || !found.value) {
        throw new Error(`createSessionFor: no payload-auth-link user ${String(userId)}`)
      }
      const record = found.value
      if (
        record.suspendedUntil !== null &&
        record.suspendedUntil !== undefined &&
        isSuspendedAt(record.suspendedUntil, wired.clock.now())
      ) {
        throw new UserSuspendedError(record.suspendedUntil)
      }
      // Walk the user's identities to one whose provider can mint the
      // session; the session belongs to the PROVIDER user (the
      // provider's own id), never synthesized from the Payload id.
      for (const identity of record.identities) {
        const required = wired.registry.require(identity.providerId)
        if (required.isErr()) {
          continue
        }
        const provider = required.value
        if (
          !provider.capabilities.has('server-session-create') ||
          provider.createProviderSession === undefined
        ) {
          continue
        }
        const expiresAt =
          options.ttlSeconds === undefined
            ? new Date(wired.clock.now().getTime() + 7 * 24 * 3600 * 1000)
            : new Date(wired.clock.now().getTime() + options.ttlSeconds * 1000)
        const created = await provider.createProviderSession(identity.providerUserId, {
          expiresAt,
          ...(options.mfaProof === undefined ? {} : { mfaProof: options.mfaProof }),
        })
        if (created.isErr()) {
          throw new Error(`createSessionFor: ${created.error.message}`)
        }
        // Audit and return the expiry the PROVIDER STORED, not the one
        // we asked for: engines that cannot honor the request must not
        // gain an audited claim they didn't fulfill.
        const storedExpiresAt = created.value.storedExpiresAt
        auditLog.info('server session created', {
          providerId: identity.providerId,
          userId: String(record.id),
          sessionId: created.value.sessionId,
          reason: options.reason,
          ...(options.actor === undefined ? {} : { actor: options.actor }),
          ...(options.mfaProof === undefined ? {} : { mfaProof: options.mfaProof }),
          expiresAt: (storedExpiresAt ?? expiresAt).toISOString(),
        })
        return {
          sessionId: created.value.sessionId,
          token: created.value.token,
          expiresAt: storedExpiresAt ?? expiresAt,
          setCookie:
            provider.sessionCookie === undefined
              ? undefined
              : await provider.sessionCookie(created.value.token),
        }
      }
      throw new ServerSessionUnsupportedError(String(userId), 'server-session-create')
    },

    async listSessions(userId) {
      // Every linked provider holds its own sessions (matching
      // `revokeAllForUser`): list them all, so an operator sees the
      // whole picture and can verify a full revocation.
      const { users } = createServices(wired, payload)
      const found = await users.findById(asUserId(userId))
      if (found.isErr() || !found.value) {
        throw new Error(`listSessions: no payload-auth-link user ${String(userId)}`)
      }
      const sessions: { readonly sessionId: string; readonly expiresAt: Date | null }[] = []
      let attempted = 0
      for (const identity of found.value.identities) {
        const required = wired.registry.require(identity.providerId)
        if (required.isErr()) {
          continue
        }
        const provider = required.value
        if (
          !provider.capabilities.has('server-session-list') ||
          provider.listProviderSessions === undefined
        ) {
          continue
        }
        attempted += 1
        const result = await provider.listProviderSessions(identity.providerUserId)
        if (result.isErr()) {
          throw new Error(`listSessions: ${result.error.message}`)
        }
        sessions.push(...result.value)
      }
      if (attempted === 0) {
        throw new ServerSessionUnsupportedError(String(userId), 'server-session-list')
      }
      return sessions
    },

    async revokeSession(sessionId) {
      // The id is a provider-verified handle (from listSessions or a
      // Session object); every BA-family provider revokes through the
      // same internalAdapter call, so walk the registry.
      let lastError = 'no provider is installed'
      for (const id of wired.registry.ids()) {
        const required = wired.registry.require(id)
        if (required.isErr()) {
          continue
        }
        const done = await required.value.revokeSession(sessionId)
        if (done.isOk()) {
          return
        }
        lastError = done.error.message
      }
      throw new Error(`revokeSession: ${lastError}`)
    },

    async revokeAllForUser(userId) {
      // Every linked provider holds its own sessions (issue #72: with
      // two linked providers, walking only the first left the second
      // provider's sessions alive), so walk them all and fail closed
      // — every provider is attempted, any failure aborts the claim.
      const { users } = createServices(wired, payload)
      const found = await users.findById(asUserId(userId))
      if (found.isErr() || !found.value) {
        throw new Error(`revokeAllForUser: no payload-auth-link user ${String(userId)}`)
      }
      const failures: string[] = []
      let attempted = 0
      for (const identity of found.value.identities) {
        const required = wired.registry.require(identity.providerId)
        if (required.isErr()) {
          continue
        }
        const provider = required.value
        if (
          !provider.capabilities.has('revoke-user-sessions') ||
          provider.revokeUserSessions === undefined
        ) {
          continue
        }
        attempted += 1
        const result = await provider.revokeUserSessions(identity.providerUserId)
        if (result.isErr()) {
          failures.push(`${identity.providerId}: ${result.error.message}`)
        }
      }
      if (attempted === 0) {
        throw new ServerSessionUnsupportedError(String(userId), 'revoke-user-sessions')
      }
      if (failures.length > 0) {
        throw new Error(`revokeAllForUser: ${failures.join('; ')}`)
      }
    },

    async verifyApiKey(key) {
      const provider = firstProviderWith(wired, 'api-key-verify')
      if (
        provider === undefined ||
        provider.capabilities.has('api-key-verify') === false ||
        provider.verifyApiKey === undefined
      ) {
        throw new Error(
          'verifyApiKey: the configured provider cannot verify API keys (capability api-key-verify)'
        )
      }
      const result = await provider.verifyApiKey(key)
      if (result.isErr()) {
        throw new Error(`verifyApiKey: ${result.error.message}`, { cause: result.error })
      }
      return result.value
    },

    async sessionCookie(token) {
      // The token does not name its provider: with more than one
      // cookie-transport provider this surface could not know whose
      // secret/name to sign with — refuse instead of silently signing
      // with the wrong one. `createSessionFor` is unambiguous (its
      // setCookie comes from the provider that minted the token).
      const capable = allProvidersWith(wired, 'server-session-create').filter(
        (provider) => provider.sessionCookie !== undefined
      )
      if (capable.length === 0) {
        throw new Error(
          'sessionCookie: the configured provider does not use a cookie session transport'
        )
      }
      if (capable.length > 1) {
        throw new Error(
          'sessionCookie: several registered providers mint cookie sessions — use createSessionFor, whose setCookie comes from the provider that minted the token'
        )
      }
      const provider = capable[0]
      if (provider === undefined || provider.sessionCookie === undefined) {
        throw new Error(
          'sessionCookie: the configured provider does not use a cookie session transport'
        )
      }
      return provider.sessionCookie(token)
    },
  }
}
