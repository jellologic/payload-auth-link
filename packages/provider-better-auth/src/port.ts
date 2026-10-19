import {
  InvalidConfigError,
  isRecord,
  parseCookieHeader,
  parseEmail,
  parsePhoneNumber,
  ProviderError,
  runProviderOperation,
  toDate,
  wellKnownProviderIds,
  type Capability,
  type CookieOptions,
  type IdentityProviderPort,
  type PhoneNumber,
  type ProviderSession,
  type SessionChannel,
  type VerifiedClaim,
  type ApiKeyVerification,
  authMethods,
  type AuthMethod,
} from '@payload-auth-link/core'
import { presentedBetterAuthCookieChunks } from './cookies.js'
import { UnsupportedApiKeyOwnerError } from './errors.js'
import type { IdentityEventBus } from './events.js'
import { MFA_METHODS, MINT_METHOD, STEP_UP_METHOD } from './session-provenance.js'

/**
 * Better Auth plugin ids whose presence this adapter maps to core
 * capabilities (PORT-2). The engine collects the ids from the
 * builder's plugin list; direct port users pass them honestly.
 * A capability is declared only when the plugin is installed AND the
 * narrowing below maps its session facts — declaring one without the
 * plugin would lie (its fields can never appear), so the set is
 * derived, never asserted wholesale.
 */
export const betterAuthPluginCapabilities: Readonly<Record<string, Capability>> = {
  admin: 'impersonation',
  'magic-link': 'magic-link',
  'email-otp': 'email-otp',
  'generic-oauth': 'oauth',
  'one-tap': 'one-tap',
  passkey: 'passkey',
  'two-factor': 'mfa',
  'phone-number': 'phone',
  anonymous: 'anonymous',
  'api-key': 'api-key-verify',
}

/**
 * Derive declared capabilities from installed plugin ids (PORT-2).
 * `revoke-user-sessions` is always declared: it rides BA core's
 * `internalAdapter.deleteUserSessions`, which needs no plugin.
 * `oauth` is also set directly (not via a plugin) when the builder
 * configured core social providers — the engine reports that as the
 * `oauth` flag. Assurance honesty: `mfa` means enrollment-mapped
 * (spike S3), and `methods` stays `'unknown'` (spike S4) for every
 * capability — declared capabilities assert the FACT mapping exists,
 * never a per-session method BA cannot report.
 */
export function betterAuthCapabilities(input: {
  readonly plugins?: readonly string[] | undefined
  readonly oauth?: boolean | undefined
  readonly impersonation?: boolean | undefined
}): ReadonlySet<Capability> {
  const capabilities = new Set<Capability>([
    'revoke-user-sessions',
    // BA core's internalAdapter.createSession/listSessions need no
    // plugin, exactly like deleteUserSessions.
    'server-session-create',
    'server-session-list',
  ])
  for (const id of input.plugins ?? []) {
    const capability = betterAuthPluginCapabilities[id]
    if (capability !== undefined) {
      capabilities.add(capability)
    }
  }
  if (input.oauth === true) {
    capabilities.add('oauth')
  }
  if (input.impersonation === true) {
    capabilities.add('impersonation')
  }
  return capabilities
}
import { errAsync, okAsync, ResultAsync } from 'neverthrow'

/** Session read input: live headers, cache and refresh disabled. */
export type BetterAuthSessionQuery = {
  headers: Headers
  query: { disableCookieCache: boolean; disableRefresh: boolean }
}

/**
 * The Better Auth server surface the port needs, stated structurally so
 * direct users pass the real instance and tests pass stubs. `getSession`
 * returns `unknown` and is narrowed below — never trusted blindly.
 */
export type BetterAuthServerApi = {
  readonly api: {
    readonly getSession: (input: BetterAuthSessionQuery) => Promise<unknown>
    /**
     * Multi-session enumeration (CAP-13b), present only with BA's
     * `multiSession` plugin. Signature-verified by BA; returns one
     * entry per presented device session.
     */
    readonly listDeviceSessions?: ((input: { headers: Headers }) => Promise<unknown>) | undefined
  }
  readonly $context: Promise<{
    readonly internalAdapter: {
      readonly deleteSession: (token: string) => Promise<void>
      /**
       * Present on every real BA instance (core internal adapter);
       * optional here so narrow hand-built stubs still typecheck —
       * `revokeUserSessions` fails with `ProviderError` when absent.
       */
      readonly deleteUserSessions?: ((userId: string) => Promise<void>) | undefined
      /**
       * BA core creates sessions server-side (`internalAdapter
       * .createSession(userId, expiresAt)`); present on every real
       * instance. Drives `createProviderSession` (#54).
       */
      readonly createSession?: ((userId: string, expiresAt: Date) => Promise<unknown>) | undefined
      /**
       * BA core enumerates one user's live sessions; drives
       * `listProviderSessions` (#54).
       */
      readonly listSessions?: ((userId: string) => Promise<unknown>) | undefined
      /**
       * BA core user lookup; present on every real instance. Gates
       * `verifyApiKey`: a key whose owner is not a user (an
       * organization-owned key) is refused (#110). Absent → every key
       * is refused (fail closed).
       */
      readonly findUserById?: ((userId: string) => Promise<unknown>) | undefined
    }
  }>
  /**
   * `@better-auth/api-key`'s server-side key verification; present
   * only with that plugin installed. Drives `verifyApiKey` (#54).
   */
  readonly verifyApiKey?: ((input: { body: { key: string } }) => Promise<unknown>) | undefined
}

/** Port wiring: the Better Auth server surface plus cookie names. */
export type BetterAuthProviderDeps = {
  readonly auth: BetterAuthServerApi
  /** From {@link getBetterAuthSessionCookieNames} (see `cookies.ts`). */
  readonly sessionCookieNames: readonly string[]
  /** Issue #124: adopt mode — `idStrategy: 'payload'` with the user model adopted. */
  readonly providerUserIdsAreDocumentIds?: boolean | undefined
  /**
   * Clearing attributes per session cookie, from
   * {@link getBetterAuthSessionCookieClearOptions} (see `cookies.ts`).
   * Used on logout; unknown names fall back to prefix-derived attributes.
   */
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
  /**
   * Non-session cookies to expire on logout, from
   * {@link getBetterAuthLogoutCookieNames} (see `cookies.ts`): BA's
   * `admin_session` impersonation cookie.
   */
  readonly logoutCookieNames?: readonly string[] | undefined
  /**
   * Whether the BA admin plugin is installed on this instance.
   * Gates the declared `'impersonation'` capability: only the admin
   * plugin can produce `session.impersonatedBy`. The engine sets
   * this from the builder's plugin list; direct users must set it
   * honestly. Defaults to `false` (capability undeclared) — the
   * actor narrowing still runs and fails closed on malformed input
   * either way.
   */
  readonly impersonation?: boolean | undefined
  /**
   * Ids of the BA plugins installed on this instance (e.g.
   * `'magic-link'`, `'two-factor'`), used to derive declared
   * capabilities via {@link betterAuthCapabilities}. The engine
   * collects them from the builder's plugin list; direct users pass
   * the ids of the plugins they actually installed.
   */
  readonly plugins?: readonly string[] | undefined
  /**
   * Whether core social OAuth providers are configured (declares
   * `'oauth'` without the `genericOAuth` plugin). Engine-set.
   */
  readonly oauth?: boolean | undefined
  /**
   * Identity lifecycle event bus (CAP-14): when present, the port
   * exposes `onIdentityEvent` subscriptions fed by the engine's
   * `databaseHooks` translation. Direct users who compose their own
   * hooks may supply their own bus from `createIdentityEventBus`.
   */
  readonly events?: IdentityEventBus | undefined
  /**
   * Coexistence window (#51): legacy payload-auth session cookie
   * names, honored READ-ONLY until the ISO date `until`. After the
   * window the names are ignored and the lookup refuses with a logged
   * reason. Minting always uses the current names.
   */
  readonly legacySessions?:
    | {
        readonly until: string
        readonly cookieNames: readonly string[]
      }
    | undefined
}

type PortFunctions = {
  /** Issue #124: adopt mode — the engine's user ids are document ids. */
  readonly providerUserIdsAreDocumentIds?: boolean | undefined
  readonly getSession: (input: BetterAuthSessionQuery) => Promise<unknown>
  readonly deleteSession: (token: string) => Promise<unknown>
  readonly deleteUserSessions: (userId: string) => Promise<unknown>
  readonly createProviderSession: (
    userId: string,
    options: { readonly expiresAt: Date; readonly mfaProof?: boolean | undefined }
  ) => Promise<unknown>
  readonly listProviderSessions: (userId: string) => Promise<unknown>
  /**
   * API-key verification (#54) and its owner gate (#110), present
   * together or not at all: a verifier without the owner lookup cannot
   * be wired, so no key can ever skip the gate.
   */
  readonly apiKeys?:
    | {
        readonly verify: (key: string) => Promise<unknown>
        /** Whether an id names a live BA user (the API-key owner gate, #110). */
        readonly isProviderUser: (userId: string) => Promise<boolean>
      }
    | undefined
  readonly buildSessionCookies: {
    /** The signed value `token.<signature>` (BA reads only the signed form). */
    readonly value: (token: string) => Promise<string>
    /** The full `Set-Cookie` line (name, attributes), for responses. */
    readonly line: (token: string) => Promise<string>
  }
  readonly listDeviceSessions?: ((input: { headers: Headers }) => Promise<unknown>) | undefined
  readonly sessionCookieNames: readonly string[]
  readonly capabilities: ReadonlySet<Capability>
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
  readonly logoutCookieNames?: readonly string[] | undefined
  readonly events?: IdentityEventBus | undefined
  /**
   * Coexistence window (#51): legacy payload-auth session cookie
   * names, honored READ-ONLY until the ISO date `until`. After the
   * window the names are ignored and the lookup refuses with a logged
   * reason. Minting always uses the current names. Exposed on the
   * port (#72) so the plugin can cross-check its own option against
   * the window that actually acts.
   */
  readonly legacySessions?:
    | {
        readonly until: string
        readonly cookieNames: readonly string[]
      }
    | undefined
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return isRecord(value) && typeof value.then === 'function'
}

function isGetSessionFunction(
  value: unknown
): value is (input: BetterAuthSessionQuery) => Promise<unknown> {
  return typeof value === 'function'
}

function isDeleteSessionFunction(value: unknown): value is (token: string) => Promise<unknown> {
  return typeof value === 'function'
}

function isListDeviceSessionsFunction(
  value: unknown
): value is (input: { headers: Headers }) => Promise<unknown> {
  return typeof value === 'function'
}

/**
 * Observed presentation channel (CAP-13a), fail-closed: ANY
 * presented `Authorization: Bearer [REDACTED]` token makes the channel
 * `'bearer'`, even when a session cookie rides along. BA's `bearer`
 * plugin overwrites the session cookie from the header token before
 * `getSession`, so a co-present (possibly dummy) cookie proves
 * nothing about which credential authenticated. Browsers never send
 * `Authorization` on cookie flows, so honest cookie clients are
 * unaffected. Observed from the incoming headers, never asserted
 * unconditionally.
 */
function observedChannel(headers: Headers): SessionChannel {
  // API keys (CAP-13): BA's api-key plugin reads `x-api-key`. A
  // presented key is the most specific signal, so it wins over a
  // co-present Bearer [REDACTED] (key sessions are admitted only by an
  // explicit `api-key` policy — off by default, D8).
  const apiKey = headers.get('x-api-key')
  if (apiKey !== null && apiKey.trim() !== '') {
    return 'api-key'
  }
  const authorization = headers.get('authorization')
  const hasBearer = authorization !== null && /^bearer\s+\S/i.test(authorization.trim())
  return hasBearer ? 'bearer' : 'cookie'
}

/**
 * Placeholder emails BA mints for identities that have no real
 * address: anonymous users (`temp-…@anonymous.placeholder.invalid`
 * by default) and SIWE wallets (`createPlaceholderEmail`, CAP-17).
 * Such an address is not an identity claim at all — it must never
 * link, whatever `emailVerified` says.
 */
export function isPlaceholderEmail(email: string): boolean {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase()
  return domain === 'placeholder.invalid' || domain.endsWith('.placeholder.invalid')
}

/**
 * Narrow BA's phone-number user fields (CAP-9) to a core claim.
 * Absent/null fields (plugin uninstalled or no number on file) map
 * to `null`. Present values of the wrong TYPE are malformed and fail
 * closed; a present string that is not E.164 yields `null` instead
 * of killing an otherwise valid email session — an unparseable
 * number simply never links by phone.
 */
function narrowPhoneClaim(user: Record<string, unknown>): VerifiedClaim<PhoneNumber> | null {
  const { phoneNumber, phoneNumberVerified } = user
  if (
    (phoneNumber === undefined || phoneNumber === null) &&
    (phoneNumberVerified === undefined || phoneNumberVerified === null)
  ) {
    return null
  }
  if (
    phoneNumberVerified !== undefined &&
    phoneNumberVerified !== null &&
    typeof phoneNumberVerified !== 'boolean'
  ) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: user phoneNumberVerified is malformed'
    )
  }
  if (phoneNumber === undefined || phoneNumber === null || phoneNumber === '') {
    return null
  }
  if (typeof phoneNumber !== 'string') {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: user phoneNumber is malformed'
    )
  }
  const parsed = parsePhoneNumber(phoneNumber)
  if (parsed.isErr()) {
    return null
  }
  return { value: parsed.value, verified: phoneNumberVerified === true }
}

function narrowSession(result: unknown, channel: SessionChannel): ProviderSession | null {
  if (result === null) {
    return null
  }
  if (!isRecord(result)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: expected a session object or null'
    )
  }
  const { session, user } = result
  if (!isRecord(session) || !isRecord(user)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: malformed session payload'
    )
  }
  if (typeof session.token !== 'string' || session.token === '') {
    throw new ProviderError(wellKnownProviderIds.betterAuth, 'getSession: session token is missing')
  }
  const expiresAt = toDate(session.expiresAt)
  if (!expiresAt) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: session expiry is missing or invalid'
    )
  }
  if (typeof user.id !== 'string' || user.id === '') {
    throw new ProviderError(wellKnownProviderIds.betterAuth, 'getSession: user id is missing')
  }
  const email = parseEmail(user.email)
  if (email.isErr()) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      `getSession: invalid user email: ${email.error.message}`
    )
  }
  if (typeof user.emailVerified !== 'boolean') {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'getSession: emailVerified flag is missing'
    )
  }
  // Admin-plugin impersonation (CAP-8a): `session.impersonatedBy` holds
  // the operator's BA user id. Absent/null (plugin unused or a plain
  // session) maps to `actor: null`; any other non-string or empty value
  // is malformed and fails closed — silently treating it as a plain
  // session would defeat impersonation auditing.
  const { impersonatedBy } = session
  let actor: ProviderSession['actor'] = null
  if (impersonatedBy !== undefined && impersonatedBy !== null) {
    if (typeof impersonatedBy !== 'string' || impersonatedBy === '') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'getSession: session impersonatedBy is malformed'
      )
    }
    actor = { providerUserId: impersonatedBy }
  }
  // Organization plugin (PORT-1): `session.activeOrganizationId` exists
  // only when the builder declared it via `customFields`. Undeclared
  // (absent/null) maps to `organizationId: null` and must not throw; a
  // present non-string or empty value is malformed and fails closed.
  const { activeOrganizationId } = session
  let organizationId: string | null = null
  if (activeOrganizationId !== undefined && activeOrganizationId !== null) {
    if (typeof activeOrganizationId !== 'string' || activeOrganizationId === '') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'getSession: session activeOrganizationId is malformed'
      )
    }
    organizationId = activeOrganizationId
  }
  // Per-session authentication method: the engine's internal
  // provenance plugin records HOW each session came into being
  // ('server-mint', 'server-step-up', 'two-factor', ...). A session
  // with no recorded method proves nothing — `'unknown'` fails closed
  // at the MFA gate. Enrollment (`user.twoFactorEnabled`) is
  // deliberately NOT consulted: enrollment is not a challenge, and
  // leaning on it made every minted session for an enrolled user
  // claim a second factor that never ran.
  const methodRaw = session['authenticationMethod']
  let methods: ProviderSession['assurance']['methods'] = 'unknown'
  let mfa: ProviderSession['assurance']['mfa'] = 'unknown'
  if (methodRaw !== undefined && methodRaw !== null) {
    // Known-method validation (fail closed): the engine writes only
    // the methods in the single-source tuple; anything else on the row
    // is a corruption, not a method.
    if (
      typeof methodRaw !== 'string' ||
      methodRaw === '' ||
      !(authMethods as readonly string[]).includes(methodRaw)
    ) {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'getSession: session authenticationMethod is malformed'
      )
    }
    const method = methodRaw as AuthMethod
    methods = [method]
    mfa = MFA_METHODS.includes(method)
  }
  const { isAnonymous } = user
  // Anonymous plugin: `user.isAnonymous` only when declared. Mapped
  // when present (CAP-10 consumes it); absent/null -> not anonymous.
  let anonymous = false
  if (isAnonymous !== undefined && isAnonymous !== null) {
    if (typeof isAnonymous !== 'boolean') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'getSession: user isAnonymous is malformed'
      )
    }
    anonymous = isAnonymous
  }
  // Placeholder emails (anonymous/SIWE, CAP-10/CAP-17) are not an
  // email identity: the claim is `null` and the session is a guest
  // at most (D3). The deprecated flat aliases still carry the raw
  // address for one minor; linking reads the claim, never them.
  const placeholder = isPlaceholderEmail(email.value)
  // The OPAQUE handle: the session ROW id (issue #80 — never the
  // bearer token). Older engines whose getSession output strips the id
  // fall back to the token; revokeSession resolves both shapes.
  const handle = typeof session.id === 'string' && session.id !== '' ? session.id : session.token
  const narrowed: ProviderSession = {
    sessionId: handle,
    providerUserId: user.id,
    email: email.value,
    emailVerified: user.emailVerified,
    expiresAt,
    identity: {
      email: placeholder ? null : { value: email.value, verified: user.emailVerified },
      phone: narrowPhoneClaim(user),
      anonymous: anonymous || placeholder,
    },
    // No per-session sign-in method exists on BA (spike S4).
    assurance: { methods, mfa },
    actor,
    organizationId,
    // Observed from the presenting headers (see `observedChannel`).
    channel,
  }
  return narrowed
}

function createPortFromFunctions(deps: PortFunctions): IdentityProviderPort {
  const providerId = wellKnownProviderIds.betterAuth
  const clearOptions = deps.sessionCookieClearOptions
  const logoutCookieNames = deps.logoutCookieNames
  const events = deps.events
  const buildSessionCookies = deps.buildSessionCookies
  const apiKeys = deps.apiKeys
  const listDeviceSessions = deps.listDeviceSessions
  const legacySessions = deps.legacySessions
  return {
    id: providerId,
    capabilities: deps.capabilities,
    sessionCookieNames: [...deps.sessionCookieNames],
    ...(clearOptions === undefined ? {} : { sessionCookieClearOptions: clearOptions }),
    ...(legacySessions === undefined
      ? {}
      : {
          legacySessions: {
            until: legacySessions.until,
            cookieNames: [...legacySessions.cookieNames],
          },
        }),
    ...(logoutCookieNames === undefined ? {} : { logoutCookieNames: [...logoutCookieNames] }),
    ...(events === undefined ? {} : { onIdentityEvent: (handler) => events.subscribe(handler) }),
    getSession(headers: Headers): ResultAsync<ProviderSession | null, ProviderError> {
      const channel = observedChannel(headers)
      return runProviderOperation(
        providerId,
        'getSession',
        () =>
          deps.getSession({ headers, query: { disableCookieCache: true, disableRefresh: true } }),
        (result) => narrowSession(result, channel)
      )
    },
    revokeSession(sessionId: string): ResultAsync<void, ProviderError> {
      return runProviderOperation(
        providerId,
        'revokeSession',
        () => deps.deleteSession(sessionId),
        () => undefined
      )
    },
    revokeUserSessions(providerUserId: string): ResultAsync<void, ProviderError> {
      // CAP-7: BA core can drop every session of a user server-side;
      // used best-effort on suspension (the Payload gate is the
      // authority, this kills the provider copies too).
      return runProviderOperation(
        providerId,
        'revokeUserSessions',
        () => deps.deleteUserSessions(providerUserId),
        () => undefined
      )
    },
    createProviderSession(
      providerUserId: string,
      options: { readonly expiresAt: Date; readonly mfaProof?: boolean | undefined }
    ): ResultAsync<
      {
        readonly sessionId: string
        readonly token: string
        readonly storedExpiresAt: Date | null
      },
      ProviderError
    > {
      return runProviderOperation(
        providerId,
        'createProviderSession',
        () => deps.createProviderSession(providerUserId, options),
        narrowCreatedSession
      )
    },
    listProviderSessions(
      providerUserId: string
    ): ResultAsync<
      readonly { readonly sessionId: string; readonly expiresAt: Date | null }[],
      ProviderError
    > {
      return runProviderOperation(
        providerId,
        'listProviderSessions',
        () => deps.listProviderSessions(providerUserId),
        narrowProviderSessions
      )
    },
    ...(apiKeys === undefined
      ? {}
      : {
          verifyApiKey: (key: string) =>
            runProviderOperation(
              providerId,
              'verifyApiKey',
              () => apiKeys.verify(key),
              (result) => narrowApiKeyVerification(result)
            ).andThen((verified) => refuseNonUserApiKeyOwner(verified, apiKeys.isProviderUser)),
        }),
    sessionCookie: (token: string) => buildSessionCookies.value(token),
    sessionCookieLine: (token: string) => buildSessionCookies.line(token),
    // Issue #124: declared by the engine for adopt mode only.
    ...(deps.providerUserIdsAreDocumentIds === true
      ? { providerUserIdsAreDocumentIds: true as const }
      : {}),
    ...(listDeviceSessions === undefined
      ? {}
      : {
          listPresentedSessionIds: (headers: Headers) =>
            runProviderOperation(
              providerId,
              'listPresentedSessionIds',
              () => listDeviceSessions({ headers }),
              (result) => narrowDeviceSessionIds(result)
            ),
        }),
    presentedLogoutCookieNames: (headers: Headers) =>
      presentedLogoutCookies(headers, deps, deps.listDeviceSessions !== undefined),
  }
}

/** The context fields the signed session cookie (#54) is built from. */
type SessionCookieContext = {
  readonly secret: string
  readonly cookieName: string
  readonly attributes: Readonly<Record<string, unknown>>
}

/**
 * Narrow the resolved `$context` to the fields BA itself uses to mint
 * the session cookie — `secret` and `authCookies.sessionToken`
 * (name + attributes, secure prefix and `maxAge` included). A context
 * without them is a wiring bug: fail closed, never mint an unsigned
 * cookie BA would refuse.
 */
function narrowSessionCookieContext(resolved: unknown): SessionCookieContext {
  if (!isRecord(resolved)) {
    throw new InvalidConfigError('Better Auth $context is not an object')
  }
  const secret = resolved.secret
  if (typeof secret !== 'string' || secret === '') {
    throw new InvalidConfigError('Better Auth $context exposes no secret')
  }
  const authCookies = resolved.authCookies
  if (!isRecord(authCookies) || !isRecord(authCookies.sessionToken)) {
    throw new InvalidConfigError('Better Auth $context exposes no authCookies.sessionToken')
  }
  const name = authCookies.sessionToken.name
  if (typeof name !== 'string' || name === '') {
    throw new InvalidConfigError('Better Auth session cookie has no name')
  }
  return {
    secret,
    cookieName: name,
    attributes: isRecord(authCookies.sessionToken.attributes)
      ? authCookies.sessionToken.attributes
      : {},
  }
}

/**
 * BA's cookie signature (its `makeSignature`): base64 of
 * HMAC-SHA256 over the value with the context secret. BA reads the
 * session token cookie back with `getSignedCookie` ONLY, so an
 * unsigned cookie resolves no session — this is what
 * `sessionCookie(token)` must produce.
 */
async function signCookieValue(value: string, secret: string): Promise<string> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(value))
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
}

/**
 * The signed session cookie for `sessionCookie(token)` (#54), built
 * from the resolved BA context (issue #72: the cookie MUST be
 * `token.<signature>` — BA only accepts the signed form) with the
 * context's own write attributes (name, Path, HttpOnly, SameSite,
 * Secure, Domain, Max-Age). The context resolves once; every call
 * after that awaits the cached read.
 *
 * Two shapes from one context (#125): the signed VALUE
 * (`token.<signature>`) for `sessionCookie` — injecting into a request
 * `Cookie` header — and the full `Set-Cookie` LINE for
 * `sessionCookieLine` (responses, `createSession().setCookie`).
 */
function buildSessionCookiesFromContext(context: PromiseLike<unknown>): {
  readonly value: (token: string) => Promise<string>
  readonly line: (token: string) => Promise<string>
} {
  const resolved = context.then(narrowSessionCookieContext)
  // The narrowing rejects when the context lacks the cookie fields;
  // without a reader that rejection would sit unhandled from port
  // construction (crashing test runs with fail-closed engines). The
  // builder below surfaces it on first use instead.
  Promise.resolve(resolved).catch(() => {})
  const line = async (token: string): Promise<string> => {
    const { secret, cookieName, attributes } = await resolved
    const signature = await signCookieValue(token, secret)
    const parts: string[] = [`${cookieName}=${token}.${signature}`]
    const path = attributes['path']
    parts.push(`Path=${typeof path === 'string' && path !== '' ? path : '/'}`)
    if (attributes['httpOnly'] !== false) {
      parts.push('HttpOnly')
    }
    const sameSite = attributes['sameSite']
    if (typeof sameSite === 'string' && sameSite !== '') {
      parts.push(`SameSite=${sameSite.charAt(0).toUpperCase()}${sameSite.slice(1)}`)
    }
    if (attributes['secure'] === true) {
      parts.push('Secure')
    }
    const domain = attributes['domain']
    if (typeof domain === 'string' && domain !== '') {
      parts.push(`Domain=${domain}`)
    }
    const maxAge = attributes['maxAge']
    if (typeof maxAge === 'number' && Number.isFinite(maxAge)) {
      parts.push(`Max-Age=${String(Math.floor(maxAge))}`)
    }
    return parts.join('; ')
  }
  const value = async (token: string): Promise<string> => {
    const { secret } = await resolved
    const signature = await signCookieValue(token, secret)
    return `${token}.${signature}`
  }
  return { value, line }
}

/**
 * #51 coexistence: read a session normally; on a miss inside the
 * legacy window, re-present legacy payload-auth cookies under the
 * current names READ-ONLY. After the window the legacy names are
 * dropped (session miss). Minting always uses current names.
 */
async function getSessionMaybeWithLegacy(
  input: BetterAuthSessionQuery,
  call: (rewritten: BetterAuthSessionQuery) => Promise<unknown>,
  sessionCookieNames: readonly string[],
  legacySessions?: {
    readonly until: string
    readonly cookieNames: readonly string[]
  }
): Promise<unknown> {
  if (legacySessions === undefined) {
    return call(input)
  }
  const headers = input.headers
  const hasCurrent = sessionCookieNames.some((name) =>
    new RegExp(`(?:^|;\\s*)${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=`).test(
      headers.get('cookie') ?? ''
    )
  )
  if (hasCurrent) {
    return call(input)
  }
  if (new Date(legacySessions.until).getTime() <= Date.now()) {
    return null
  }
  const translated = new Headers(headers)
  const cookieHeader = headers.get('cookie') ?? ''
  // Map EVERY legacy name to the current name with the same suffix
  // (`.sig` signatures ride along with their token cookie).
  let copied = false
  for (const legacyName of legacySessions.cookieNames) {
    const match = new RegExp(
      `(?:^|;\\s*)${legacyName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=([^;]+)`
    ).exec(cookieHeader)
    if (match === null) {
      continue
    }
    const base = legacyName.replace(/^__Secure-/, '').replace(/\.[^.]+$/, '')
    const suffix = legacyName.replace(/^__Secure-/, '').slice(base.length)
    for (const currentName of sessionCookieNames) {
      const currentBase = currentName.replace(/^__Secure-/, '').replace(/\.[^.]+$/, '')
      const currentSuffix = currentName.replace(/^__Secure-/, '').slice(currentBase.length)
      if (currentSuffix === suffix) {
        translated.append('cookie', `${currentName}=${match[1]}`)
        copied = true
        break
      }
    }
  }
  if (!copied) {
    return null
  }
  return call({ ...input, headers: translated })
}

/**
 * Narrow BA core's createSession result to the core shape. Malformed
 * results fail closed — a session whose id or token is missing could
 * never be verified or revoked.
 */
function narrowCreatedSession(result: unknown): {
  sessionId: string
  token: string
  storedExpiresAt: Date | null
} {
  // The session id is the OPAQUE row id — never the bearer token (the
  // token rides a dedicated field, consumed only to set the cookie).
  // The stored expiry is read from the row BA actually wrote, not the
  // requested one.
  if (
    !isRecord(result) ||
    typeof result.id !== 'string' ||
    result.id === '' ||
    typeof result.token !== 'string' ||
    result.token === ''
  ) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'createProviderSession: expected a session row with an id and a token'
    )
  }
  return {
    sessionId: result.id,
    token: result.token,
    storedExpiresAt: toDate(result.expiresAt),
  }
}

/**
 * Narrow BA core's listSessions result. Malformed entries fail closed
 * for the whole enumeration.
 */
function narrowProviderSessions(result: unknown): { sessionId: string; expiresAt: Date | null }[] {
  if (!Array.isArray(result)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'listProviderSessions: expected an array'
    )
  }
  return result.map((entry) => {
    // The handle is the OPAQUE session row id — never the token (the
    // token is a bearer credential; a devices page that lists session
    // ids would otherwise expose one live credential per session,
    // issue #80). The port resolves the id to the token server-side
    // inside revokeSession — one id type, verified deletion.
    if (!isRecord(entry) || typeof entry.id !== 'string' || entry.id === '') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'listProviderSessions: expected sessions with an id'
      )
    }
    const expires = entry.expiresAt
    return {
      sessionId: entry.id,
      expiresAt: expires instanceof Date ? expires : null,
    }
  })
}

/**
 * Narrow `@better-auth/api-key`'s verifyApiKey response to the core
 * verification shape. A null/false response (unknown key) narrows to
 * null; a malformed `key` block fails closed.
 *
 * The owner: `@better-auth/api-key` 1.7.x names the key's owner
 * `referenceId` (the user id for user-owned keys); 1.6-era builds named
 * it `userId`. `referenceId` wins, `userId` is the fallback; a key
 * block carrying neither fails closed (issue #88 — reading only
 * `userId` threw for every valid 1.7 key).
 */
/**
 * The API-key owner gate (#110): `@better-auth/api-key` names the
 * owner `referenceId`, which is an ORGANIZATION id for keys of a
 * `references: 'organization'` configuration. The verify response
 * does not say which, so the owner must resolve to a live BA user —
 * otherwise the key is refused with {@link UnsupportedApiKeyOwnerError}
 * instead of handing an organization id out as `userId`. The lookup
 * is wired together with the verifier (`PortFunctions.apiKeys`), and a
 * lookup that cannot run (no `internalAdapter.findUserById`) rejects,
 * so the key is refused (fail closed).
 */
function refuseNonUserApiKeyOwner(
  verified: ApiKeyVerification | null,
  isProviderUser: (userId: string) => Promise<boolean>
): ResultAsync<ApiKeyVerification | null, ProviderError> {
  if (verified === null) {
    return okAsync(null)
  }
  return ResultAsync.fromPromise(
    isProviderUser(verified.userId),
    (cause) => new ProviderError(wellKnownProviderIds.betterAuth, 'verifyApiKey', { cause })
  ).andThen((isUser) =>
    isUser ? okAsync(verified) : errAsync(new UnsupportedApiKeyOwnerError(verified.userId))
  )
}

function narrowApiKeyVerification(result: unknown): ApiKeyVerification | null {
  if (result === null || result === undefined) {
    return null
  }
  if (!isRecord(result) || result.valid !== true || !isRecord(result.key)) {
    return null
  }
  const key = result.key
  const owner =
    typeof key.referenceId === 'string' && key.referenceId !== ''
      ? key.referenceId
      : typeof key.userId === 'string' && key.userId !== ''
        ? key.userId
        : null
  if (owner === null) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'verifyApiKey: key block is missing its owner (referenceId / userId)'
    )
  }
  return {
    userId: owner,
    name: typeof key.name === 'string' ? key.name : null,
    start: typeof key.start === 'string' ? key.start : null,
    prefix: typeof key.prefix === 'string' ? key.prefix : null,
    metadata: key.metadata ?? null,
    rateLimitEnabled: typeof key.rateLimitEnabled === 'boolean' ? key.rateLimitEnabled : null,
    rateLimitRemaining:
      typeof key.remaining === 'number'
        ? key.remaining
        : typeof key.remaining === 'string' && key.remaining !== ''
          ? Number(key.remaining)
          : null,
    expiresAt:
      typeof key.expiresAt === 'string'
        ? new Date(key.expiresAt)
        : key.expiresAt instanceof Date
          ? key.expiresAt
          : null,
    permissions: typeof key.permissions === 'string' ? key.permissions : null,
  }
}

/**
 * Narrow `listDeviceSessions` output (CAP-13b) to session handles.
 * The handles come from BA's signature-verified enumeration — never
 * parsed out of the lowercased cookie-name suffix (spike S6).
 * Malformed entries fail closed for the whole enumeration: a partial
 * list would silently leave sessions alive after logout.
 */
function narrowDeviceSessionIds(result: unknown): readonly string[] {
  if (!Array.isArray(result)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'listDeviceSessions: expected an array'
    )
  }
  // Opaque row ids where the enumeration carries them (issue #80);
  // tokens as the fallback — revokeSession resolves both shapes.
  const handles: string[] = []
  for (const entry of result) {
    if (!isRecord(entry) || !isRecord(entry.session)) {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'listDeviceSessions: malformed entry'
      )
    }
    const { token, id } = entry.session
    if (typeof id === 'string' && id !== '') {
      handles.push(id)
      continue
    }
    if (typeof token !== 'string' || token === '') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'listDeviceSessions: session token is missing'
      )
    }
    handles.push(token)
  }
  return handles
}

/**
 * Per-request logout cookie names, never parsed for values:
 *
 * - presented multi-session cookies (CAP-13b, only with the
 *   multi-session plugin): BA names them
 *   `${sessionTokenName}_multi-${token.toLowerCase()}` (spike S6);
 *   revocation goes through the verified enumeration above;
 * - presented chunks (`<name>.0` … `<name>.<n>`) of every session and
 *   logout cookie (#110): BA's chunking stores split an oversized
 *   cookie-cache `session_data` / `account_data` cookie, and the chunk
 *   count follows the payload size, so only the request knows them.
 *   BA never chunks the other names, so enumerating their chunks only
 *   ever clears residue.
 */
function presentedLogoutCookies(
  headers: Headers,
  deps: Pick<PortFunctions, 'sessionCookieNames' | 'logoutCookieNames'>,
  multiSession: boolean
): readonly string[] {
  const header = headers.get('cookie')
  if (header === null || header === '') {
    return []
  }
  const presented = [...parseCookieHeader(header).keys()]
  const names: string[] = []
  if (multiSession) {
    for (const name of presented) {
      if (deps.sessionCookieNames.some((base) => name.startsWith(`${base}_multi-`))) {
        names.push(name)
      }
    }
  }
  names.push(
    ...presentedBetterAuthCookieChunks(presented, [
      ...deps.sessionCookieNames,
      ...(deps.logoutCookieNames ?? []),
    ])
  )
  return names
}

/**
 * `IdentityProviderPort` over a Better Auth server instance. Session reads
 * bypass the cookie cache and refresh (`disableCookieCache`,
 * `disableRefresh`): the plugin verifies the authoritative database
 * session, so a revoked-but-cached session can never authorize. The
 * revocable handle is the session token, revoked through BA's own
 * `internalAdapter.deleteSession` (which also clears secondary storage).
 */
export function createBetterAuthProvider(deps: BetterAuthProviderDeps): IdentityProviderPort {
  const verifyApiKey = deps.auth.verifyApiKey
  return createPortFromFunctions({
    providerUserIdsAreDocumentIds: deps.providerUserIdsAreDocumentIds === true,
    getSession: (input) =>
      getSessionMaybeWithLegacy(
        input,
        deps.auth.api.getSession,
        deps.sessionCookieNames,
        deps.legacySessions
      ),
    deleteSession: (handle) =>
      deps.auth.$context.then(async (ctx) => {
        // The handle is the OPAQUE session row id (issue #80): resolve
        // it to the token SERVER-SIDE, then delete by token — verified
        // both directions (a row must exist, and must be gone).
        const internalAdapter = ctx.internalAdapter as unknown as {
          deleteSession?: ((token: string) => Promise<unknown>) | undefined
          findSessions?: ((tokens: string[]) => Promise<unknown>) | undefined
        }
        const adapter = (
          ctx as unknown as {
            adapter?: {
              findOne?: (input: {
                model: string
                where: readonly { field: string; value: string }[]
              }) => Promise<unknown>
            }
          }
        ).adapter
        const findSessions = internalAdapter.findSessions
        const findOne = adapter?.findOne
        if (findSessions === undefined) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'revokeSession: internalAdapter.findSessions is unavailable; deletion cannot be verified'
          )
        }
        // The input may be (a) an OPAQUE session row id — from the
        // server API's listSessions/createSessionFor (issue #80) — or
        // (b) a raw session TOKEN — from BA's own logout internals
        // (CAP-13b multi-session logout, impersonation logout).
        // Resolve whichever shape arrives; an id is never a token and
        // a token is never an id, so the lookup is unambiguous.
        let token: string | null = null
        const row =
          findOne === undefined
            ? null
            : ((await findOne({
                model: 'session',
                where: [{ field: 'id', value: handle }],
              })) as { token?: unknown } | null)
        if (isRecord(row) && typeof row.token === 'string' && row.token !== '') {
          token = row.token
        } else {
          const byToken = (await findSessions([handle])) as unknown[]
          if (Array.isArray(byToken) && byToken.length > 0) {
            token = handle
          }
        }
        if (token === null) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'revokeSession: no session exists for the given id'
          )
        }
        await ctx.internalAdapter.deleteSession(token)
        const after = (await findSessions([token])) as unknown[]
        if (Array.isArray(after) && after.length > 0) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'revokeSession: no session was deleted for the given id'
          )
        }
      }),
    deleteUserSessions: (userId) =>
      deps.auth.$context.then((ctx) => {
        const { deleteUserSessions } = ctx.internalAdapter
        if (deleteUserSessions === undefined) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'revokeUserSessions: internalAdapter.deleteUserSessions is unavailable'
          )
        }
        return deleteUserSessions(userId)
      }),
    createProviderSession: (userId, options) =>
      deps.auth.$context.then((ctx) => {
        const createSession = ctx.internalAdapter.createSession as unknown as
          | ((
              userId: string,
              dontRememberMe: boolean,
              override: Record<string, unknown>,
              overrideAll: boolean
            ) => Promise<unknown>)
          | undefined
        if (createSession === undefined) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'createProviderSession: internalAdapter.createSession is unavailable'
          )
        }
        // BA's real signature is (userId, dontRememberMe, override,
        // overrideAll): dontRememberMe truthy forces the 24h expiry and
        // override.expiresAt only applies with overrideAll. Record the
        // authentication method on the row so no minted session can
        // inherit an MFA claim it never earned.
        return createSession(
          userId,
          false,
          {
            expiresAt: options.expiresAt,
            authenticationMethod: options.mfaProof === true ? STEP_UP_METHOD : MINT_METHOD,
          },
          true
        )
      }),
    listProviderSessions: (userId) =>
      deps.auth.$context.then((ctx) => {
        const listSessions = ctx.internalAdapter.listSessions
        if (listSessions === undefined) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'listProviderSessions: internalAdapter.listSessions is unavailable'
          )
        }
        return listSessions(userId) as Promise<{ id: string; expiresAt: Date | null }[]>
      }),
    ...(verifyApiKey === undefined
      ? {}
      : {
          apiKeys: {
            verify: (key: string) => verifyApiKey({ body: { key } }),
            isProviderUser: (userId: string) =>
              deps.auth.$context.then(async (ctx) => {
                const find = ctx.internalAdapter.findUserById
                if (find === undefined) {
                  throw new ProviderError(
                    wellKnownProviderIds.betterAuth,
                    'verifyApiKey: internalAdapter.findUserById is unavailable'
                  )
                }
                return isRecord(await find(userId))
              }),
          },
        }),
    ...(deps.legacySessions === undefined ? {} : { legacySessions: deps.legacySessions }),
    // #54/#72: the signed session cookie (value + line, #125), built
    // from the instance's own resolved context (secret + cookie
    // attributes).
    buildSessionCookies: buildSessionCookiesFromContext(deps.auth.$context),
    ...(deps.auth.api.listDeviceSessions === undefined
      ? {}
      : { listDeviceSessions: deps.auth.api.listDeviceSessions }),
    sessionCookieNames: deps.sessionCookieNames,
    capabilities: betterAuthCapabilities({
      plugins: deps.plugins,
      oauth: deps.oauth,
      impersonation: deps.impersonation,
    }),
    ...(deps.sessionCookieClearOptions === undefined
      ? {}
      : { sessionCookieClearOptions: deps.sessionCookieClearOptions }),
    ...(deps.logoutCookieNames === undefined ? {} : { logoutCookieNames: deps.logoutCookieNames }),
    ...(deps.events === undefined ? {} : { events: deps.events }),
  })
}

/**
 * Same port, but the instance arrives as `unknown` and is shape-checked at
 * wiring time. The engine uses this: `Auth` is invariant in its options,
 * so a generically-typed instance cannot be converted to
 * {@link BetterAuthServerApi} statically; the runtime shape check plus the
 * engine integration tests (which run a real instance through here) close
 * the gap. Not exported from the barrel — same-package use only.
 */
export function createBetterAuthProviderFromUnknown(
  auth: unknown,
  sessionCookieNames: readonly string[],
  sessionCookieClearOptions?: (name: string) => CookieOptions | undefined,
  logoutCookieNames?: readonly string[],
  options?: {
    readonly impersonation?: boolean | undefined
    readonly plugins?: readonly string[] | undefined
    readonly oauth?: boolean | undefined
    readonly events?: IdentityEventBus | undefined
    readonly legacySessions?:
      | {
          readonly until: string
          readonly cookieNames: readonly string[]
        }
      | undefined
    /** Issue #124: adopt mode, `idStrategy: 'payload'`, user model adopted. */
    readonly providerUserIdsAreDocumentIds?: boolean | undefined
  }
): IdentityProviderPort {
  if (!isRecord(auth)) {
    throw new InvalidConfigError('Better Auth instance must be an object')
  }
  const { api, $context } = auth
  if (!isRecord(api) || !isGetSessionFunction(api.getSession)) {
    throw new InvalidConfigError('Better Auth instance exposes no api.getSession function')
  }
  const getSession = api.getSession
  // Multi-session enumeration exists only with the plugin; its
  // absence is normal, a present non-function is a wiring bug.
  const listDeviceSessions = isListDeviceSessionsFunction(api.listDeviceSessions)
    ? api.listDeviceSessions
    : undefined
  if (!isThenable($context)) {
    throw new InvalidConfigError('Better Auth instance exposes no $context promise')
  }
  const context = $context
  const internalCall = (method: 'deleteSession' | 'deleteUserSessions', arg: string) =>
    Promise.resolve(
      context.then((resolved) => {
        if (!isRecord(resolved) || !isRecord(resolved.internalAdapter)) {
          throw new InvalidConfigError('Better Auth $context exposes no internalAdapter')
        }
        const candidate: unknown = resolved.internalAdapter[method]
        if (!isDeleteSessionFunction(candidate)) {
          throw new InvalidConfigError(`Better Auth internalAdapter exposes no ${method} function`)
        }
        return candidate(arg)
      })
    )
  const internalAdapterCall = (
    method: 'createSession' | 'listSessions' | 'findSessions' | 'findUserById',
    run: (candidate: (...args: never[]) => unknown) => unknown
  ) =>
    Promise.resolve(
      context.then((resolved) => {
        if (!isRecord(resolved) || !isRecord(resolved.internalAdapter)) {
          throw new InvalidConfigError('Better Auth $context exposes no internalAdapter')
        }
        const candidate: unknown = resolved.internalAdapter[method]
        if (typeof candidate !== 'function') {
          throw new InvalidConfigError(`Better Auth internalAdapter exposes no ${method} function`)
        }
        return run(candidate as (...args: never[]) => unknown)
      })
    )
  const verifyApiKey =
    typeof api.verifyApiKey === 'function'
      ? (key: string) =>
          (api.verifyApiKey as (input: { body: { key: string } }) => Promise<unknown>)({
            body: { key },
          })
      : undefined
  return createPortFromFunctions({
    providerUserIdsAreDocumentIds: options?.providerUserIdsAreDocumentIds === true,
    getSession: (input) =>
      getSessionMaybeWithLegacy(
        input,
        (rewritten) => getSession(rewritten),
        sessionCookieNames,
        options?.legacySessions
      ),
    deleteSession: (handle) =>
      // The handle is the OPAQUE session row id (issue #80): resolve it
      // to the token SERVER-SIDE through the adapter, then delete by
      // token — fail closed both directions (a row must exist, and
      // must be gone afterwards).
      Promise.resolve(
        context.then(async (resolved) => {
          if (!isRecord(resolved) || !isRecord(resolved.internalAdapter)) {
            throw new InvalidConfigError('Better Auth $context exposes no internalAdapter')
          }
          const adapter = resolved.adapter
          const findOne =
            isRecord(adapter) && typeof adapter['findOne'] === 'function'
              ? (adapter['findOne'] as (input: {
                  model: string
                  where: readonly { field: string; value: string }[]
                }) => Promise<unknown>)
              : undefined
          const found =
            findOne === undefined
              ? null
              : await findOne({ model: 'session', where: [{ field: 'id', value: handle }] })
          return Promise.resolve(found).then((foundRow) => {
            // The input may be an OPAQUE row id (server API, issue
            // #80) or a raw TOKEN (BA's own logout internals).
            let token: string | null = null
            if (
              isRecord(foundRow) &&
              typeof foundRow['token'] === 'string' &&
              foundRow['token'] !== ''
            ) {
              token = foundRow['token']
            }
            if (token === null && findOne === undefined) {
              // Bare-fixture fallback: no adapter to resolve ids with,
              // so the input is treated as the token itself.
              token = handle
            }
            if (token === null) {
              throw new ProviderError(
                wellKnownProviderIds.betterAuth,
                'revokeSession: no session exists for the given id'
              )
            }
            const deleteSession = (resolved.internalAdapter as Record<string, unknown>)[
              'deleteSession'
            ] as (token: string) => Promise<unknown>
            if (typeof deleteSession !== 'function') {
              throw new InvalidConfigError('Better Auth internalAdapter exposes no deleteSession')
            }
            return deleteSession(token).then(() =>
              internalAdapterCall('findSessions', (verify) =>
                (verify as (tokens: string[]) => Promise<unknown>)([token]).then((after) => {
                  if (Array.isArray(after) && after.length > 0) {
                    throw new ProviderError(
                      wellKnownProviderIds.betterAuth,
                      'revokeSession: no session was deleted for the given id'
                    )
                  }
                  return undefined
                })
              )
            )
          })
        })
      ),
    deleteUserSessions: (userId) => internalCall('deleteUserSessions', userId),
    createProviderSession: (userId, options) =>
      // BA's real signature is (userId, dontRememberMe, override,
      // overrideAll): dontRememberMe truthy forces the 24h expiry and
      // override.expiresAt only applies with overrideAll. Record the
      // authentication method on the row so no minted session can
      // inherit an MFA claim it never earned.
      internalAdapterCall('createSession', (createSession) =>
        (
          createSession as (
            userId: string,
            dontRememberMe: boolean,
            override: Record<string, unknown>,
            overrideAll: boolean
          ) => Promise<unknown>
        )(
          userId,
          false,
          {
            expiresAt: options.expiresAt,
            authenticationMethod: options.mfaProof === true ? STEP_UP_METHOD : MINT_METHOD,
          },
          true
        )
      ),
    listProviderSessions: (userId) =>
      internalAdapterCall('listSessions', (listSessions) =>
        (listSessions as (userId: string) => Promise<unknown>)(userId)
      ),
    ...(verifyApiKey === undefined
      ? {}
      : {
          apiKeys: {
            verify: verifyApiKey,
            isProviderUser: (userId: string) =>
              internalAdapterCall('findUserById', (findUserById) =>
                (findUserById as (id: string) => Promise<unknown>)(userId)
              ).then((user) => isRecord(user)),
          },
        }),
    // #54/#72: the signed session cookie (value + line, #125), built
    // from the instance's own resolved context (secret + cookie
    // attributes).
    buildSessionCookies: buildSessionCookiesFromContext(context),
    ...(listDeviceSessions === undefined ? {} : { listDeviceSessions }),
    sessionCookieNames,
    capabilities: betterAuthCapabilities({
      plugins: options?.plugins,
      oauth: options?.oauth,
      impersonation: options?.impersonation,
    }),
    ...(sessionCookieClearOptions === undefined ? {} : { sessionCookieClearOptions }),
    ...(logoutCookieNames === undefined ? {} : { logoutCookieNames }),
    ...(options?.events === undefined ? {} : { events: options.events }),
    ...(options?.legacySessions === undefined ? {} : { legacySessions: options.legacySessions }),
  })
}
