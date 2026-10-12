import { resolveSlugs, type IdentityProviderPort } from '@payload-auth-link/core'
import { betterAuth, type BetterAuthOptions, type BetterAuthPlugin } from 'better-auth'
import type { CollectionConfig, Payload } from 'payload'
import { createPayloadDatabaseAdapter } from './adapter.js'
import {
  createBetterAuthCollections,
  defaultBetterAuthSlugs,
  type BetterAuthCollectionsAccess,
  type BetterAuthCollectionSlugs,
  type BetterAuthCustomField,
  type BetterAuthCustomModel,
  type BetterAuthModelKey,
} from './collections.js'
import {
  getBetterAuthSessionCookieClearOptions,
  getBetterAuthSessionCookieNames,
} from './cookies.js'
import { createBetterAuthProviderFromUnknown } from './port.js'

/** Engine wiring: Payload access plus the builder's Better Auth options. */
export type BetterAuthEngineInput<TOptions extends Omit<BetterAuthOptions, 'database'>> = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Override any default Better Auth collection slug. */
  readonly slugs?: Partial<BetterAuthCollectionSlugs> | undefined
  /** Custom fields on core models (`additionalFields`, plugin fields). */
  readonly customFields?:
    Partial<Record<BetterAuthModelKey, readonly BetterAuthCustomField[]>> | undefined
  /** Custom plugin models (e.g. the organization plugin's tables). */
  readonly customModels?: readonly BetterAuthCustomModel[] | undefined
  /** Payload query depth for adapter reads. Defaults to 0. */
  readonly depth?: number | undefined
  /** Access control for the system collections. Defaults to deny-all. */
  readonly collectionsAccess?: BetterAuthCollectionsAccess | undefined
  /**
   * The builder's Better Auth options, passed through verbatim except for
   * `database` (wired to Payload here, so it is omitted from this type)
   * and `emailAndPassword` (see below).
   *
   * Framework cookie plugins (`nextCookies()`, `tanstackStartCookies()`,
   * …) belong in `options.plugins`, exactly as Better Auth documents
   * them — the engine never touches the plugin list, so any present or
   * future cookie plugin works without the engine knowing about it.
   */
  readonly options: TOptions
}

/** Composed engine: instance, port, collections, slugs, cookie names. */
export type BetterAuthEngine<AuthType> = {
  /** The composed Better Auth instance; mount it with the Next adapter. */
  readonly auth: AuthType
  /** The instance behind `IdentityProviderPort`; register it with the plugin. */
  readonly provider: IdentityProviderPort
  /** Payload collections for the Better Auth models; spread into the config. */
  readonly collections: CollectionConfig[]
  /** Resolved slugs (defaults plus overrides). */
  readonly slugs: BetterAuthCollectionSlugs
  /** Session cookie names for middleware fast-paths and logout clearing. */
  readonly sessionCookieNames: readonly string[]
}

/**
 * Compose a Better Auth instance on Payload storage: the Payload database
 * adapter, secure credential defaults, the `IdentityProviderPort`, and
 * the Payload collections.
 *
 * The return type is inferred so Better Auth's own option-driven typing
 * (plugin endpoints, `$Infer` session types) flows through untouched.
 * Builder options (including `plugins`) pass through verbatim — the
 * engine appends nothing, so framework cookie plugins are declared by
 * the builder exactly as Better Auth documents them.
 *
 * Secure defaults: when `emailAndPassword` is present but silent on
 * `requireEmailVerification`, verification is required — builders must
 * explicitly opt out (the example does, and documents why). The user
 * bridge needs no `databaseHooks`: Payload users are provisioned lazily
 * and idempotently at session verification (see the plugin session
 * service), so no signup ordering can strand a provider user.
 */
export function createBetterAuthEngine<
  TOptions extends Omit<BetterAuthOptions, 'database'>,
  TPlugins extends readonly BetterAuthPlugin[] | undefined,
>(input: BetterAuthEngineInput<TOptions> & { options: { plugins?: TPlugins } }) {
  const slugs: BetterAuthCollectionSlugs = resolveSlugs(defaultBetterAuthSlugs, input.slugs)
  const database = createPayloadDatabaseAdapter({
    getPayload: input.getPayload,
    slugs,
    depth: input.depth,
    customFields: input.customFields,
    customModels: input.customModels,
  })
  const emailAndPassword =
    input.options.emailAndPassword === undefined
      ? undefined
      : { requireEmailVerification: true, ...input.options.emailAndPassword }
  // The builder's `plugins` pass through verbatim inside
  // `input.options`: the engine never appends framework cookie plugins
  // (see the input docs), so there is no second guessable API beside
  // Better Auth's own `plugins` convention. `TPlugins` (bound on the
  // input type) keeps plugin endpoints inferred on `auth.api`.
  const auth = betterAuth({ ...input.options, database, emailAndPassword })
  const sessionCookieNames = getBetterAuthSessionCookieNames(input.options)
  const sessionCookieClearOptions = getBetterAuthSessionCookieClearOptions(input.options)
  // `Auth` is invariant in its options, so the generically-typed instance
  // cannot convert to the port's structural type statically; the
  // shape-checked constructor closes the gap (see `port.ts`).
  const provider = createBetterAuthProviderFromUnknown(
    auth,
    sessionCookieNames,
    sessionCookieClearOptions
  )
  const collections = createBetterAuthCollections({
    slugs: input.slugs,
    access: input.collectionsAccess,
    customFields: input.customFields,
    customModels: input.customModels,
  })
  return { auth, provider, collections, slugs, sessionCookieNames }
}
