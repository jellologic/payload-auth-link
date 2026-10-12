import {
  InvalidConfigError,
  normalizeBaseUrl,
  resolveOrigin,
  resolveSlugs,
} from '@payload-auth-link/core'
import { Auth, type AuthConfig } from '@auth/core'
import type { CollectionConfig, Payload } from 'payload'
import { createAuthJsAdapter } from './adapter.js'
import { createAuthLinkCallbacks } from './callbacks.js'
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
   * The builder's Auth.js config, passed through verbatim except for
   * `adapter` (wired to Payload here, so it is omitted from this type),
   * `callbacks` (chained with the claims the port needs — see
   * `callbacks.ts`), and the secure defaults below.
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

function providerType(provider: AuthConfig['providers'][number]): string | undefined {
  if (typeof provider !== 'function') {
    return provider.type
  }
  // Factories are a valid provider form; Auth.js itself calls them with
  // `{}` at normalization, so the engine inspects them the same way.
  // A factory that throws here would throw identically on first request.
  try {
    return provider({})?.type
  } catch (error) {
    throw new InvalidConfigError(
      `Auth.js provider factory threw when called (Auth.js calls factories the same way): ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

function hasCredentialsProvider(options: Omit<AuthConfig, 'adapter'>): boolean {
  return options.providers.some((provider) => providerType(provider) === 'credentials')
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
      ...createAuthLinkCallbacks(input.options.callbacks),
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
  }

  const provider = createAuthJsProvider({
    sessions,
    sessionCookieNames,
    sessionCookieClearOptions,
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
