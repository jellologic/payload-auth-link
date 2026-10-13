import {
  createIdentityEventEmitter,
  InvalidConfigError,
  normalizeBaseUrl,
  nullLogger,
  resolveOrigin,
  resolveSlugs,
  type LoggerPort,
} from '@payload-auth-link/core'
import { Auth, type AuthConfig } from '@auth/core'
import type { CollectionConfig, Payload } from 'payload'
import { createAuthJsAdapter } from './adapter.js'
import {
  createAuthLinkCallbacks,
  createAuthLinkEvents,
  type AuthLinkTrustOptions,
} from './callbacks.js'
import {
  createAuthJsCollections,
  defaultAuthJsSlugs,
  type AuthJsCollectionsAccess,
  type AuthJsCollectionSlugs,
} from './collections.js'
import {
  getAuthJsSessionCookieClearOptions,
  getAuthJsSessionCookieNames,
  type AuthJsCookieOptions,
} from './cookies.js'
import { createAuthJsProvider, type AuthJsSessionApi } from './port.js'

/** Engine wiring: Payload access plus the builder's Auth.js config. */
export type AuthJsEngineInput = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Override any default Auth.js collection slug. */
  readonly slugs?: Partial<AuthJsCollectionSlugs> | undefined
  /** Payload query depth for adapter reads. Defaults to 0. */
  readonly depth?: number | undefined
  /** Access control for the system collections. Defaults to deny-all. */
  readonly collectionsAccess?: AuthJsCollectionsAccess | undefined
  /**
   * Site origin. Derives secure cookie names (https → secure +
   * `__Secure-` prefix) and — more importantly — anchors the internal
   * session read: without it the origin falls back to request host
   * headers, which a client can spoof. Defaults to `AUTH_URL` (Auth.js's
   * own env), then to http. Required in production behind a proxy, and
   * production deployments must set a canonical https origin (without
   * one the secure-cookie rule falls back to `NODE_ENV` detection —
   * see the Auth.js guide's production note).
   */
  readonly baseURL?: string | undefined
  /**
   * Chunk slots after the base session cookie name (`.0`, `.1`, …).
   * Defaults to 3 (~12k of token); raise it when custom claims push
   * JWTs past that. Must be a non-negative integer.
   */
  readonly chunkSlots?: number | undefined
  /**
   * Allow-list of OAuth/OIDC provider ids (e.g. `['google', 'acme-oidc']`)
   * whose asserted `email_verified === true` may stamp the adapter
   * user's `emailVerified` through `updateUser` (D6). Auth.js otherwise
   * creates every OAuth user with `emailVerified: null`, so the plugin
   * refuses to link them. Defaults to empty: no provider is trusted and
   * nothing is ever stamped. A stamp additionally requires the profile
   * email to be the user's own email; `email_verified` false or absent
   * never stamps. Combining an allow-listed provider with that
   * provider's `allowDangerousEmailAccountLinking: true` fails fast
   * with `InvalidConfigError` — dangerous linking would attach the
   * account to a pre-existing user by email alone, defeating the
   * verified-email gate this option relies on.
   */
  readonly trustProviderEmailVerification?: readonly string[] | undefined
  /**
   * Structured logger for wiring-time risky-linking warnings (CAP-12).
   * Defaults to silent (`nullLogger`) — pass the same logger as the
   * plugin to see them. Warnings name the offending setting; they
   * never go to `console.*`.
   */
  readonly logger?: LoggerPort | undefined
  /**
   * Turn every risky-linking warning into a wiring-time
   * `InvalidConfigError` (CAP-12). Risky means any provider with
   * `allowDangerousEmailAccountLinking: true`, which attaches accounts
   * by email alone on sign-in. The plugin's verified-email gate still
   * guards Payload linking either way; this option makes the
   * provider-side loosening fail fast instead of merely loud.
   * Combining a `trustProviderEmailVerification` provider with
   * dangerous linking already throws regardless of this option (D6).
   * Defaults to `false` (warn only).
   */
  readonly strictLinking?: boolean | undefined
  /**
   * The builder's Auth.js config, passed through verbatim except for
   * `adapter` (wired to Payload here, so it is omitted from this type),
   * `callbacks` and the `signIn` event (chained with the claims and
   * D6 stamping the port needs — see `callbacks.ts`), and the secure
   * defaults below.
   */
  readonly options: Omit<AuthConfig, 'adapter'>
}

/** Composed engine: config, port, collections, slugs, cookie names. */
export type AuthJsEngine = {
  /** The composed Auth.js config; mount it with the Next adapter. */
  readonly config: AuthConfig
  /** The config behind `IdentityProviderPort`; register it with the plugin. */
  readonly provider: ReturnType<typeof createAuthJsProvider>
  /** Payload collections for the Auth.js models; spread into the config. */
  readonly collections: CollectionConfig[]
  /** Resolved slugs (defaults plus overrides). */
  readonly slugs: AuthJsCollectionSlugs
  /** Session cookie names for middleware fast-paths and logout clearing. */
  readonly sessionCookieNames: readonly string[]
  /** Handle an Auth.js request (`(request) => Auth(request, config)`). */
  readonly handleRequest: (request: Request) => Promise<Response>
}

type InspectedProvider = {
  readonly id?: string | undefined
  readonly type?: string | undefined
  readonly allowDangerousEmailAccountLinking?: boolean | undefined
}

function inspectProvider(provider: AuthConfig['providers'][number]): InspectedProvider | undefined {
  if (typeof provider !== 'function') {
    return provider
  }
  // Factories are a valid provider form; Auth.js itself calls them with
  // `{}` at normalization, so the engine inspects them the same way.
  // A factory that throws here would throw identically on first request.
  try {
    return provider({})
  } catch (error) {
    throw new InvalidConfigError(
      `Auth.js provider factory threw when called (Auth.js calls factories the same way): ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

/**
 * CAP-12: collect every provider with
 * `allowDangerousEmailAccountLinking: true` and report it — one loud
 * `LoggerPort` warning naming the setting and provider by default, or
 * one `InvalidConfigError` naming them all under `strictLinking`.
 * Runs after the D6 check, which keeps its always-throw precedence
 * for trusted providers.
 */
function reportDangerousLinking(
  options: Omit<AuthConfig, 'adapter'>,
  opts: { readonly logger: LoggerPort; readonly strictLinking: boolean }
): void {
  const dangerous: string[] = []
  for (const provider of options.providers) {
    const inspected = inspectProvider(provider)
    if (inspected?.allowDangerousEmailAccountLinking === true) {
      dangerous.push(inspected.id ?? '<unknown provider id>')
    }
  }
  if (dangerous.length === 0) {
    return
  }
  if (opts.strictLinking) {
    throw new InvalidConfigError(
      `Auth.js strictLinking rejects allowDangerousEmailAccountLinking on provider(s) ${dangerous
        .map((id) => `"${id}"`)
        .join(', ')}: dangerous linking attaches accounts by email alone`
    )
  }
  for (const providerId of dangerous) {
    opts.logger.warn(
      `Auth.js risky account-linking config: provider "${providerId}" sets allowDangerousEmailAccountLinking: true, so Auth.js may link accounts by email alone on sign-in. Payload linking still requires a verified email, but the provider may link internally on weaker proof; set strictLinking: true to fail fast instead.`,
      { setting: 'allowDangerousEmailAccountLinking', providerId }
    )
  }
}

function hasCredentialsProvider(options: Omit<AuthConfig, 'adapter'>): boolean {
  return options.providers.some((provider) => inspectProvider(provider)?.type === 'credentials')
}

/**
 * D6 fail-fast: trusting a provider's `email_verified` while that same
 * provider may link accounts by email alone would let an unverified
 * OAuth email claim attach to (and then verify) a pre-existing user.
 */
function assertTrustIsNotDangerous(
  options: Omit<AuthConfig, 'adapter'>,
  trusted: readonly string[]
): void {
  for (const providerId of trusted) {
    if (typeof providerId !== 'string' || providerId.trim() === '') {
      throw new InvalidConfigError(
        'Auth.js trustProviderEmailVerification entries must be non-empty provider ids'
      )
    }
  }
  if (trusted.length === 0) {
    return
  }
  for (const provider of options.providers) {
    const inspected = inspectProvider(provider)
    if (
      inspected?.id !== undefined &&
      trusted.includes(inspected.id) &&
      inspected.allowDangerousEmailAccountLinking === true
    ) {
      throw new InvalidConfigError(
        `Auth.js trustProviderEmailVerification cannot be combined with allowDangerousEmailAccountLinking on provider "${inspected.id}": dangerous linking attaches accounts by email alone, defeating the verified-email gate`
      )
    }
  }
}

/**
 * Origin for the internal session read, via the shared resolver. The
 * configured `baseURL` (`AUTH_URL`, validated at wiring) wins whenever
 * it is set. The host fallback stays allowed here: unlike the web
 * verifier's real `fetch`, this URL feeds an in-process `Auth()`
 * call, so a spoofed host cannot exfiltrate the cookie — it only
 * affects Auth.js's internal host checks.
 */
function sessionRequestUrl(
  baseURL: string | undefined,
  basePath: string,
  headers: Headers
): string {
  const origin = resolveOrigin({ baseUrl: baseURL, headers, allowHostFallback: true })
  return new URL(`${basePath}/session`, origin).toString()
}

/**
 * Anchor an incoming request's origin to the configured `baseURL` before
 * raw `@auth/core` sees it. Core derives every host-dependent decision
 * (action URLs, redirect and callbackUrl validation) from `request.url`,
 * and honors forwarded host headers while `trustHost` is true — which it
 * must be (see above). Rewriting only the origin (protocol + host + port,
 * never path or query) keeps a spoofed `Host` / `X-Forwarded-Host` from
 * steering Auth.js. Matching origins (and an unset `baseURL`) pass the
 * original request through untouched, so correct deployments see zero
 * behavior change. Exported for the engine suite.
 */
export function anchorRequestOrigin(request: Request, baseURL: string | undefined): Request {
  if (baseURL === undefined) {
    return request
  }
  const canonical = new URL(baseURL)
  const url = new URL(request.url)
  if (url.origin === canonical.origin) {
    return request
  }
  url.protocol = canonical.protocol
  url.host = canonical.host
  return new Request(url.toString(), request)
}

/**
 * Compose Auth.js on Payload storage: the Payload database adapter, the
 * claims callbacks the port needs, the `IdentityProviderPort`, and the
 * Payload collections.
 *
 * Secure defaults and fail-fasts (spike findings, Phase 4):
 * - `basePath` defaults to `/api/authjs` (coexists with Better Auth's
 *   `/api/auth`); `trustHost` defaults to true because raw `@auth/core`
 *   rejects every request otherwise (`UntrustedHost`, unconditionally —
 *   there is no `AUTH_URL` rescue at this layer since `Auth()` never runs
 *   `setEnvDefaults`). Host strictness comes from origin anchoring
 *   instead: `handleRequest` rewrites the request origin to the
 *   configured `baseURL` before core sees it, so forwarded host headers
 *   cannot steer Auth.js redirects or callback validation.
 * - A missing secret (`options.secret` and `AUTH_SECRET` both unset)
 *   throws here instead of 500ing on first use.
 * - A Credentials provider with an effective `database` session strategy
 *   throws here: Auth.js rejects that combination at config time with
 *   loud 500s (`UnsupportedStrategy`), so the engine fails faster with
 *   the fix attached. Credentials REQUIRES explicit jwt strategy.
 *
 * JWT sessions are stateless bearer tokens: revocation deletes database
 * sessions and is a no-op for JWT (logout expires the cookies, but a
 * copied token replays until `maxAge`). Credentials deployments therefore
 * default to a short `session.maxAge` of one hour unless the builder sets
 * one explicitly. A server-side denylist is deliberately not built
 * (stateless JWTs need new shared infrastructure to revoke — see
 * `docs/SPRINT.md` Accepted risks); the mitigation is this short default
 * window plus explicit `maxAge` tuning per deployment.
 */
export function createAuthJsEngine(input: AuthJsEngineInput): AuthJsEngine {
  const slugs: AuthJsCollectionSlugs = resolveSlugs(defaultAuthJsSlugs, input.slugs)
  const adapter = createAuthJsAdapter({ getPayload: input.getPayload, slugs, depth: input.depth })
  const trustedProviders = input.trustProviderEmailVerification ?? []
  assertTrustIsNotDangerous(input.options, trustedProviders)
  reportDangerousLinking(input.options, {
    logger: input.logger ?? nullLogger(),
    strictLinking: input.strictLinking === true,
  })
  if (trustedProviders.length > 0 && adapter.updateUser === undefined) {
    throw new InvalidConfigError(
      'Auth.js trustProviderEmailVerification requires an adapter updateUser to stamp emailVerified'
    )
  }
  const trust: AuthLinkTrustOptions = {
    trustProviderEmailVerification: trustedProviders,
    updateUser: (user) => {
      if (adapter.updateUser === undefined) {
        throw new InvalidConfigError(
          'Auth.js trustProviderEmailVerification requires an adapter updateUser to stamp emailVerified'
        )
      }
      return adapter.updateUser(user)
    },
  }
  const strategy = input.options.session?.strategy ?? 'database'
  if (strategy === 'database' && hasCredentialsProvider(input.options)) {
    throw new InvalidConfigError(
      'Auth.js credentials require explicit session: { strategy: "jwt" } (Auth.js rejects credentials with database sessions)'
    )
  }
  if (input.options.secret === undefined && process.env.AUTH_SECRET === undefined) {
    throw new InvalidConfigError(
      'Auth.js secret is required: set options.secret or the AUTH_SECRET environment variable'
    )
  }
  if (
    input.chunkSlots !== undefined &&
    (!Number.isInteger(input.chunkSlots) || input.chunkSlots < 0)
  ) {
    throw new InvalidConfigError('Auth.js chunkSlots must be a non-negative integer')
  }
  const basePath = input.options.basePath ?? '/api/authjs'
  // Stateless JWTs replay until `maxAge` after logout (no revocation —
  // see above), so credentials deployments get a short one-hour default
  // instead of Auth.js's thirty days. Explicit values always win; the
  // default applies only when a Credentials provider is present.
  const session =
    hasCredentialsProvider(input.options) && input.options.session?.maxAge === undefined
      ? { ...input.options.session, maxAge: 3600 }
      : input.options.session
  // CAP-14: Auth.js events are translated onto this emitter; the
  // port exposes its subscriptions as `onIdentityEvent`.
  const lifecycleEvents = createIdentityEventEmitter()
  const config: AuthConfig = {
    ...input.options,
    basePath,
    ...(session === undefined ? {} : { session }),
    // Must stay truthy: raw core's `assertConfig` answers every request
    // with `UntrustedHost` otherwise. See `anchorRequestOrigin` for the
    // host hardening this default would otherwise forgo.
    trustHost: input.options.trustHost ?? true,
    adapter,
    callbacks: {
      ...input.options.callbacks,
      ...createAuthLinkCallbacks(input.options.callbacks, trust),
    },
    events: {
      ...input.options.events,
      ...createAuthLinkEvents(input.options.events, trust, {
        emitter: lifecycleEvents,
        logger: input.logger ?? nullLogger(),
      }),
    },
  }
  const baseURL = input.baseURL ?? process.env.AUTH_URL
  // Fail fast at wiring: a malformed origin must never reach a request.
  if (baseURL !== undefined) {
    normalizeBaseUrl(baseURL)
  }
  const cookieOptions: AuthJsCookieOptions = {
    useSecureCookies: input.options.useSecureCookies,
    ...(baseURL === undefined ? {} : { baseURL }),
    ...(input.options.cookies?.sessionToken?.name === undefined
      ? {}
      : { sessionTokenName: input.options.cookies.sessionToken.name }),
    ...(input.options.cookies?.sessionToken?.options === undefined
      ? {}
      : { sessionTokenOptions: input.options.cookies.sessionToken.options }),
    ...(input.chunkSlots === undefined ? {} : { chunkSlots: input.chunkSlots }),
  }
  const sessionCookieNames = getAuthJsSessionCookieNames(cookieOptions)
  const sessionCookieClearOptions = getAuthJsSessionCookieClearOptions(cookieOptions)

  const sessions: AuthJsSessionApi = {
    readSession: async (headers) => {
      const cookie = headers.get('cookie')
      if (!cookie) {
        return null
      }
      // The configured origin wins: request host headers are client input
      // and must never choose where session cookies are forwarded. The
      // host fallback is a local-development convenience only — production
      // deployments behind a proxy must set `baseURL`/`AUTH_URL`.
      const sessionUrl = sessionRequestUrl(baseURL, basePath, headers)
      const response = await Auth(
        new Request(sessionUrl, {
          headers: { cookie, accept: 'application/json' },
        }),
        config
      )
      if (!response.ok) {
        return null
      }
      return (await response.json()) as unknown
    },
    revokeSession: async (sessionId) => {
      if (strategy === 'database') {
        await adapter.deleteSession?.(sessionId)
      }
      // JWT sessions are stateless: nothing server-side to revoke. The
      // plugin's logout response expires the cookies.
    },
    // CAP-7: database sessions are rows in `aj-sessions` keyed by the
    // adapter user id — delete them all through the Local API. JWT
    // deployments omit this (and the capability with it): the
    // Payload-side suspension gate still refuses at verify time.
    ...(strategy === 'database'
      ? {
          revokeUserSessions: async (providerUserId: string) => {
            const payload = await input.getPayload()
            await payload.delete({
              collection: slugs.session,
              where: { userId: { equals: providerUserId } },
              overrideAccess: true,
            })
          },
        }
      : {}),
  }

  const provider = createAuthJsProvider({
    sessions,
    sessionCookieNames,
    sessionCookieClearOptions,
    events: lifecycleEvents,
    // PORT-2 capability derivation inputs: one `type` per configured
    // provider (factories resolved by `inspectProvider`).
    providerTypes: input.options.providers
      .map((candidate) => inspectProvider(candidate)?.type)
      .filter((type): type is string => typeof type === 'string'),
    databaseSessions: strategy === 'database',
  })
  const collections = createAuthJsCollections({
    slugs: input.slugs,
    access: input.collectionsAccess,
  })
  return {
    config,
    provider,
    collections,
    slugs,
    sessionCookieNames,
    handleRequest: (request) => Auth(anchorRequestOrigin(request, baseURL), config),
  }
}
