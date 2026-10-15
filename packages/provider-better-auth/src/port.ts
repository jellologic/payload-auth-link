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
} from '@payload-auth-link/core'
import type { IdentityEventBus } from './events.js'

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
import type { ResultAsync } from 'neverthrow'

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
   * The session cookie's write attributes for
   * `sessionCookie(token)` (#54): the engine derives the name and
   * secure flag from the builder's BA options (secure-cookie rule +
   * `__Secure-` prefix). Absent = the port omits `sessionCookie`.
   */
  readonly sessionCookieSpec?:
    | {
        readonly name: string
        readonly secure: boolean
        readonly sameSite: 'lax' | 'strict' | 'none'
      }
    | undefined
}

type PortFunctions = {
  readonly getSession: (input: BetterAuthSessionQuery) => Promise<unknown>
  readonly deleteSession: (token: string) => Promise<unknown>
  readonly deleteUserSessions: (userId: string) => Promise<unknown>
  readonly createProviderSession: (userId: string, expiresAt: Date) => Promise<unknown>
  readonly listProviderSessions: (userId: string) => Promise<unknown>
  readonly verifyApiKey?: ((key: string) => Promise<unknown>) | undefined
  readonly buildSessionCookie?: ((token: string) => string) | undefined
  readonly listDeviceSessions?: ((input: { headers: Headers }) => Promise<unknown>) | undefined
  readonly sessionCookieNames: readonly string[]
  readonly capabilities: ReadonlySet<Capability>
  readonly sessionCookieClearOptions?: ((name: string) => CookieOptions | undefined) | undefined
  readonly logoutCookieNames?: readonly string[] | undefined
  readonly events?: IdentityEventBus | undefined
  /**
   * The session cookie's write attributes for
   * `sessionCookie(token)` (#54): the engine derives the name and
   * secure flag from the builder's BA options (secure-cookie rule +
   * `__Secure-` prefix). Absent = the port omits `sessionCookie`.
   */
  readonly sessionCookieSpec?:
    | {
        readonly name: string
        readonly secure: boolean
        readonly sameSite: 'lax' | 'strict' | 'none'
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
  // Two-factor plugin (spike S3): BA marks no per-session MFA proof;
  // the only signal is enrollment on `user.twoFactorEnabled`, present
  // only when declared. Absent/null -> `'unknown'`; a present
  // non-boolean is malformed and fails closed.
  const { twoFactorEnabled, isAnonymous } = user
  let mfa: ProviderSession['assurance']['mfa'] = 'unknown'
  if (twoFactorEnabled !== undefined && twoFactorEnabled !== null) {
    if (typeof twoFactorEnabled !== 'boolean') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'getSession: user twoFactorEnabled is malformed'
      )
    }
    mfa = twoFactorEnabled
  }
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
  const narrowed: ProviderSession = {
    sessionId: session.token,
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
    assurance: { methods: 'unknown', mfa },
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
  return {
    id: providerId,
    capabilities: deps.capabilities,
    sessionCookieNames: [...deps.sessionCookieNames],
    ...(clearOptions === undefined ? {} : { sessionCookieClearOptions: clearOptions }),
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
      options: { readonly expiresAt: Date }
    ): ResultAsync<{ readonly sessionId: string; readonly token: string }, ProviderError> {
      return runProviderOperation(
        providerId,
        'createProviderSession',
        () => deps.createProviderSession(providerUserId, options.expiresAt),
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
    ...(deps.verifyApiKey === undefined
      ? {}
      : {
          verifyApiKey: (key: string) =>
            runProviderOperation(
              providerId,
              'verifyApiKey',
              () => {
                const verify = deps.verifyApiKey
                return verify === undefined ? Promise.resolve(null) : verify(key)
              },
              (result) => narrowApiKeyVerification(result)
            ),
        }),
    ...(deps.buildSessionCookie === undefined
      ? {}
      : { sessionCookie: buildSessionCookieVia(deps.buildSessionCookie) }),
    ...(deps.listDeviceSessions === undefined
      ? {}
      : {
          listPresentedSessionIds: (headers: Headers) =>
            runProviderOperation(
              providerId,
              'listPresentedSessionIds',
              // Narrowed from unknown below; the explicit local keeps
              // one stable binding for the closure.
              () => {
                const list = deps.listDeviceSessions
                return list === undefined ? Promise.resolve([]) : list({ headers })
              },
              (result) => narrowDeviceSessionIds(result)
            ),
          presentedLogoutCookieNames: (headers: Headers) =>
            presentedMultiSessionCookieNames(headers, deps.sessionCookieNames),
        }),
  }
}

/**
 * Narrow `listDeviceSessions` output (CAP-13b) to session tokens.
 * The tokens come from BA's signature-verified enumeration — never
 * parsed out of the lowercased cookie-name suffix (spike S6).
 * Malformed entries fail closed for the whole enumeration: a partial
 * list would silently leave sessions alive after logout.
 */
function buildSessionCookieVia(build: (token: string) => string): (token: string) => string {
  return (token: string) => build(token)
}

function buildSessionCookieFor(spec: {
  name: string
  secure: boolean
  sameSite: 'lax' | 'strict' | 'none'
}): (token: string) => string {
  const sameSite = spec.sameSite.charAt(0).toUpperCase() + spec.sameSite.slice(1)
  return (token: string) =>
    `${spec.name}=${token}; Path=/; HttpOnly; SameSite=${sameSite}` +
    (spec.secure ? '; Secure' : '')
}

/**
 * Narrow BA core's createSession result to the core shape. Malformed
 * results fail closed — a session whose id or token is missing could
 * never be verified or revoked.
 */
function narrowCreatedSession(result: unknown): { sessionId: string; token: string } {
  if (!isRecord(result) || typeof result.id !== 'string' || typeof result.token !== 'string') {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'createProviderSession: expected a session with id and token'
    )
  }
  return { sessionId: result.id, token: result.token }
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
    if (!isRecord(entry) || typeof entry.id !== 'string') {
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
 */
function narrowApiKeyVerification(result: unknown): ApiKeyVerification | null {
  if (result === null || result === undefined) {
    return null
  }
  if (!isRecord(result) || result.valid !== true || !isRecord(result.key)) {
    return null
  }
  const key = result.key
  if (typeof key.userId !== 'string' || key.userId === '') {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'verifyApiKey: key block is missing its user id'
    )
  }
  return {
    userId: key.userId,
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

function narrowDeviceSessionIds(result: unknown): readonly string[] {
  if (!Array.isArray(result)) {
    throw new ProviderError(
      wellKnownProviderIds.betterAuth,
      'listDeviceSessions: expected an array'
    )
  }
  const tokens: string[] = []
  for (const entry of result) {
    if (!isRecord(entry) || !isRecord(entry.session)) {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'listDeviceSessions: malformed entry'
      )
    }
    const { token } = entry.session
    if (typeof token !== 'string' || token === '') {
      throw new ProviderError(
        wellKnownProviderIds.betterAuth,
        'listDeviceSessions: session token is missing'
      )
    }
    tokens.push(token)
  }
  return tokens
}

/**
 * Names of presented multi-session cookies (CAP-13b): BA names them
 * `${sessionTokenName}_multi-${token.toLowerCase()}` (spike S6), so
 * they exist only per-request. Names only — values are never read
 * here; revocation goes through the verified enumeration above.
 */
function presentedMultiSessionCookieNames(
  headers: Headers,
  sessionCookieNames: readonly string[]
): readonly string[] {
  const header = headers.get('cookie')
  if (header === null || header === '') {
    return []
  }
  const presented = parseCookieHeader(header)
  const names: string[] = []
  for (const name of presented.keys()) {
    if (sessionCookieNames.some((base) => name.startsWith(`${base}_multi-`))) {
      names.push(name)
    }
  }
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
  return createPortFromFunctions({
    getSession: (input) => deps.auth.api.getSession(input),
    deleteSession: (token) =>
      deps.auth.$context.then((ctx) => ctx.internalAdapter.deleteSession(token)),
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
    createProviderSession: (userId, expiresAt) =>
      deps.auth.$context.then((ctx) => {
        const createSession: ((userId: string, expiresAt: Date) => Promise<unknown>) | undefined =
          ctx.internalAdapter.createSession
        if (createSession === undefined) {
          throw new ProviderError(
            wellKnownProviderIds.betterAuth,
            'createProviderSession: internalAdapter.createSession is unavailable'
          )
        }
        return createSession(userId, expiresAt)
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
    ...(deps.auth.verifyApiKey === undefined
      ? {}
      : {
          verifyApiKey: (key: string) =>
            (deps.auth.verifyApiKey as (i: { body: { key: string } }) => Promise<unknown>)({
              body: { key },
            }),
        }),
    ...(deps.sessionCookieSpec === undefined
      ? {}
      : {
          buildSessionCookie: buildSessionCookieFor(deps.sessionCookieSpec),
        }),
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
    readonly sessionCookieSpec?:
      | {
          readonly name: string
          readonly secure: boolean
          readonly sameSite: 'lax' | 'strict' | 'none'
        }
      | undefined
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
    method: 'createSession' | 'listSessions',
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
  const sessionCookieSpec = options?.sessionCookieSpec
  return createPortFromFunctions({
    getSession: (input) => getSession(input),
    deleteSession: (token) => internalCall('deleteSession', token),
    deleteUserSessions: (userId) => internalCall('deleteUserSessions', userId),
    createProviderSession: (userId, expiresAt) =>
      internalAdapterCall('createSession', (createSession) =>
        (createSession as (userId: string, expiresAt: Date) => Promise<unknown>)(userId, expiresAt)
      ),
    listProviderSessions: (userId) =>
      internalAdapterCall('listSessions', (listSessions) =>
        (listSessions as (userId: string) => Promise<unknown>)(userId)
      ),
    ...(verifyApiKey === undefined ? {} : { verifyApiKey }),
    ...(sessionCookieSpec === undefined
      ? {}
      : { buildSessionCookie: buildSessionCookieFor(sessionCookieSpec) }),
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
  })
}
