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
 * when `'dev-only'` and `NODE_ENV` is `'production'`.
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
 */
const serverRegistry = new WeakMap<Payload, WiredOptions>()

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
  /** The provider's signed session cookie for one session token. */
  readonly sessionCookie: (token: string) => string
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
  // 'dev-only': refuse on a production runtime.
  return process.env.NODE_ENV !== 'production'
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

async function resolveIdentity(
  wired: WiredOptions,
  payload: Payload,
  userId: number | string,
  capability: Capability
): Promise<{ provider: IdentityProviderPort; providerUserId: string }> {
  const { users } = createServices(wired, payload)
  const found = await users.findById(asUserId(userId))
  if (found.isErr() || !found.value) {
    throw new Error(`no payload-auth-link user ${String(userId)}`)
  }
  process.stdout.write(
    `DBG-resolve user=${String(userId)} cap=${capability} identities=${JSON.stringify(found.value.identities.map((i) => i.providerId))} registry=${wired.registry.ids().join(',')}\n`
  )
  for (const identity of found.value.identities) {
    const required = wired.registry.require(identity.providerId)
    if (required.isErr()) {
      continue
    }
    const provider = required.value
    if (provider.capabilities.has(capability)) {
      return { provider, providerUserId: identity.providerUserId }
    }
  }
  throw new ServerSessionUnsupportedError(String(userId), capability)
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
          process.stdout.write(`DBG require failed: ${identity.providerId}\n`)
          continue
        }
        const provider = required.value
        process.stdout.write(
          `DBG provider ${identity.providerId} caps=${[...provider.capabilities].join(',')} hasMethod=${String(provider.createProviderSession !== undefined)} identities=${record.identities.length}\n`
        )
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
        })
        if (created.isErr()) {
          throw new Error(`createSessionFor: ${created.error.message}`)
        }
        auditLog.info('server session created', {
          providerId: identity.providerId,
          userId: String(record.id),
          sessionId: created.value.sessionId,
          reason: options.reason,
          ...(options.actor === undefined ? {} : { actor: options.actor }),
          expiresAt: expiresAt.toISOString(),
        })
        return {
          sessionId: created.value.sessionId,
          token: created.value.token,
          expiresAt,
          setCookie: provider.sessionCookie?.(created.value.token),
        }
      }
      throw new ServerSessionUnsupportedError(String(userId), 'server-session-create')
    },

    async listSessions(userId) {
      const { provider, providerUserId } = await resolveIdentity(
        wired,
        payload,
        userId,
        'server-session-list'
      )
      if (provider.listProviderSessions === undefined) {
        throw new ServerSessionUnsupportedError(String(userId), 'server-session-list')
      }
      const result = await provider.listProviderSessions(providerUserId)
      if (result.isErr()) {
        throw new Error(`listSessions: ${result.error.message}`)
      }
      return result.value
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
      const { provider, providerUserId } = await resolveIdentity(
        wired,
        payload,
        userId,
        'revoke-user-sessions'
      )
      if (provider.revokeUserSessions === undefined) {
        throw new ServerSessionUnsupportedError(String(userId), 'revoke-user-sessions')
      }
      const result = await provider.revokeUserSessions(providerUserId)
      if (result.isErr()) {
        throw new Error(`revokeAllForUser: ${result.error.message}`)
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
        throw new Error(`verifyApiKey: ${result.error.message}`)
      }
      return result.value
    },

    sessionCookie(token) {
      const provider = firstProviderWith(wired, 'server-session-create')
      if (provider === undefined || provider.sessionCookie === undefined) {
        throw new Error(
          'sessionCookie: the configured provider does not use a cookie session transport'
        )
      }
      return provider.sessionCookie(token)
    },
  }
}
