import {
  InvalidConfigError,
  assertSupportedVersion,
  isRecord,
  nullLogger,
  readInstalledVersion,
  resolveSlugs,
  type IdentityProviderPort,
  type LoggerPort,
  type VersionRange,
} from '@payload-auth-link/core'
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
  type BetterAuthSchemaMap,
} from './collections.js'
import {
  getBetterAuthLogoutCookieNames,
  getBetterAuthSessionCookieClearOptions,
  getBetterAuthSessionCookieNames,
} from './cookies.js'
import { createIdentityEventBus } from './events.js'
import { deriveBetterAuthSchema } from './derive-schema.js'
import { createBetterAuthProviderFromUnknown } from './port.js'

/** Engine wiring: Payload access plus the builder's Better Auth options. */
export type BetterAuthEngineInput<TOptions extends Omit<BetterAuthOptions, 'database'>> = {
  /** Resolves the Payload instance (cached `getPayload` in Next.js). */
  readonly getPayload: () => Promise<Payload>
  /** Override any default Better Auth collection slug. */
  readonly slugs?: Partial<BetterAuthCollectionSlugs> | undefined
  /**
   * Adopt existing collections for these Better Auth models
   * (issue #49): the engine creates no `ba-*` collection for an
   * adopted model and serves it from the host slug instead — the
   * payload-auth layout boots with zero row moves. The host keeps its
   * access, hooks, versions, and admin config; its extra fields are
   * invisible to Better Auth and survive every write (the adapter
   * writes partial updates only).
   */
  readonly schemaMap?: BetterAuthSchemaMap | undefined
  /**
   * `'payload'` (adopted models only) makes the Payload document id
   * the Better Auth row id, so existing ids never move:
   * `schemaMap: { user: { slug: 'users' } }, idStrategy: 'payload'`.
   * `'ba'` (default) keeps the provider id in a dedicated column on
   * the collections the engine creates.
   */
  readonly idStrategy?: 'ba' | 'payload' | undefined
  /** Custom fields on core models (`additionalFields`, plugin fields). */
  readonly customFields?:
    Partial<Record<BetterAuthModelKey, readonly BetterAuthCustomField[]>> | undefined
  /** Custom plugin models (e.g. the organization plugin's tables). */
  readonly customModels?: readonly BetterAuthCustomModel[] | undefined
  /**
   * Derive `customFields`/`customModels` from Better Auth's own
   * `getAuthTables(options)` (issue #17) and merge them UNDER the
   * builder's explicit declarations — a hand declaration always wins
   * over a derived one, and the derived remainder fills the gaps.
   * Strict hand-declared mode is unchanged when this is absent.
   */
  readonly autoDeclare?: boolean | undefined
  /** Payload query depth for adapter reads. Defaults to 0. */
  readonly depth?: number | undefined
  /** Access control for the system collections. Defaults to deny-all. */
  readonly collectionsAccess?: BetterAuthCollectionsAccess | undefined
  /**
   * Structured logger for wiring-time risky-linking warnings (CAP-12).
   * Defaults to silent (`nullLogger`) — pass the same logger as the
   * plugin to see them. Warnings name the offending
   * `account.accountLinking` setting; they never go to `console.*`.
   */
  readonly logger?: LoggerPort | undefined
  /**
   * Turn every risky-linking warning into a wiring-time
   * `InvalidConfigError` (CAP-12). Risky means a Better Auth setting
   * that can let an unverified email claim link accounts inside the
   * provider: `account.accountLinking.trustedProviders` naming a
   * provider without `requireEmailVerification`,
   * `allowDifferentEmails: true`, `requireLocalEmailVerified: false`,
   * or `updateUserInfoOnLink: true`. The plugin's verified-email gate
   * still guards Payload linking either way; this option makes the
   * provider-side loosening fail fast instead of merely loud.
   * Defaults to `false` (warn only).
   */
  readonly strictLinking?: boolean | undefined
  /**
   * The builder's Better Auth options, passed through verbatim except for
   * `database` (wired to Payload here, so it is omitted from this type),
   * `emailAndPassword` (see below), and
   * `account.accountLinking.updateUserInfoOnLink`, which the engine
   * forces off so a link can never rewrite `email`/`emailVerified`
   * (CAP-12; see `strictLinking`).
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
  /** The adoption map the engine serves (issue #49). */
  readonly schemaMap: BetterAuthSchemaMap
  /** Session cookie names for middleware fast-paths and logout clearing. */
  readonly sessionCookieNames: readonly string[]
}

/** One risky account-linking setting found at wiring time (CAP-12). */
type RiskyLinkingFinding = {
  readonly setting: string
  readonly detail: string
  readonly providerId?: string | undefined
}

/**
 * Whether the builder statically requires email verification for one
 * trusted provider. Better Auth reads this per social provider
 * (`socialProviders.<id>.requireEmailVerification`); the special
 * `email-password` entry follows `emailAndPassword`, where this engine
 * defaults the requirement on. Providers declared elsewhere (e.g.
 * inside a `genericOAuth` plugin) are not statically visible here, so
 * they count as unverified for this check — fail loud, never assume.
 */
function providerRequiresEmailVerification(
  options: Omit<BetterAuthOptions, 'database'>,
  providerId: string
): boolean {
  if (providerId === 'email-password') {
    return (
      options.emailAndPassword !== undefined &&
      options.emailAndPassword.requireEmailVerification !== false
    )
  }
  const socialProviders: unknown = options.socialProviders
  if (!isRecord(socialProviders)) {
    return false
  }
  const entry: unknown = socialProviders[providerId]
  return isRecord(entry) && entry.requireEmailVerification === true
}

/**
 * CAP-12: collect `account.accountLinking` looseners actually present
 * in the installed Better Auth options. `disableImplicitLinking: false`
 * is deliberately not a finding on its own: it is Better Auth's
 * default and implicit linking still demands a verified provider
 * email or a trusted provider — the trusted-provider case below is
 * the loosening. `updateUserInfoOnLink` is a finding because this
 * composition must guarantee a link can never rewrite the provider
 * user's `email`/`emailVerified` (installed 1.7.7 already destructures
 * those fields out in `applyUpdateUserInfoOnLink`, but the guarantee
 * must not depend on upstream staying that way).
 */
function findRiskyLinkingSettings(
  options: Omit<BetterAuthOptions, 'database'>
): RiskyLinkingFinding[] {
  const linking = options.account?.accountLinking
  if (linking === undefined || linking.enabled === false) {
    // Account linking is off entirely, so no linking setting can bite.
    return []
  }
  const findings: RiskyLinkingFinding[] = []
  // `trustedProviders` and `requireLocalEmailVerified` only loosen
  // *implicit* linking; with `disableImplicitLinking: true` Better
  // Auth links nothing on sign-in, so they are inert there.
  const trusted = linking.disableImplicitLinking === true ? undefined : linking.trustedProviders
  if (typeof trusted === 'function') {
    findings.push({
      setting: 'account.accountLinking.trustedProviders',
      detail:
        'is a dynamic function, so wiring cannot verify that every trusted provider sets requireEmailVerification; trusted providers may link same-email accounts without a verified provider email',
    })
  } else if (trusted !== undefined) {
    for (const providerId of trusted) {
      if (typeof providerId === 'string' && providerId !== '') {
        if (!providerRequiresEmailVerification(options, providerId)) {
          findings.push({
            setting: 'account.accountLinking.trustedProviders',
            providerId,
            detail: `includes "${providerId}" without requireEmailVerification for that provider, so Better Auth may link same-email accounts on that provider's word alone`,
          })
        }
      }
    }
  }
  if (linking.allowDifferentEmails === true) {
    findings.push({
      setting: 'account.accountLinking.allowDifferentEmails',
      detail:
        'is true, allowing manual linking of accounts whose email differs from the user email (upstream warns this can enable account takeover)',
    })
  }
  if (linking.requireLocalEmailVerified === false && linking.disableImplicitLinking !== true) {
    findings.push({
      setting: 'account.accountLinking.requireLocalEmailVerified',
      detail:
        'is false, so implicit linking may attach an OAuth identity to a pre-registered local user whose email was never verified',
    })
  }
  if (linking.updateUserInfoOnLink === true) {
    findings.push({
      setting: 'account.accountLinking.updateUserInfoOnLink',
      detail:
        'is true; this engine forces it off so linking can never rewrite email or emailVerified in this composition',
    })
  }
  return findings
}

/**
 * Report CAP-12 findings: throw one `InvalidConfigError` naming every
 * setting under `strictLinking`, otherwise one loud `LoggerPort`
 * warning per finding. The plugin's verified-email gate remains the
 * authority for Payload linking regardless.
 */
function reportRiskyLinkingSettings(
  findings: readonly RiskyLinkingFinding[],
  opts: { readonly logger: LoggerPort; readonly strictLinking: boolean }
): void {
  if (findings.length === 0) {
    return
  }
  if (opts.strictLinking) {
    throw new InvalidConfigError(
      `Better Auth strictLinking rejects risky account-linking config: ${findings
        .map((finding) => `${finding.setting} ${finding.detail}`)
        .join('; ')}`
    )
  }
  for (const finding of findings) {
    opts.logger.warn(
      `Better Auth risky account-linking config: ${finding.setting} ${finding.detail}. Payload linking still requires a verified email, but the provider may link internally on weaker proof; set strictLinking: true to fail fast instead.`,
      {
        setting: finding.setting,
        ...(finding.providerId === undefined ? {} : { providerId: finding.providerId }),
      }
    )
  }
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
 * bridge provisions Payload users lazily and idempotently at session
 * verification (see the plugin session service), so no signup
 * ordering can strand a provider user. The engine does compose
 * `databaseHooks` for CAP-14 lifecycle translation (user update /
 * delete, account delete → core `IdentityEvent`s on the port's
 * `onIdentityEvent`), preserving any builder-supplied hooks.
 */
/**
 * better-auth versions this release validated (Phase-1 bisect): the
 * type-level floor is 1.7.6 (BA's adapter `modelKey` types), and the
 * band admits only the validated 1.7 line — BA satellites force
 * minors (B12), so an unvalidated minor must fail here, typed and
 * before any DB write, never as a missing adapter method
 * mid-request. Widened only by the compatibility matrix, never by
 * optimism.
 */
export const supportedBetterAuthBand: readonly VersionRange[] = [
  { min: '1.7.6', maxExclusive: '1.8.0' },
]

type EngineDeclarations = {
  readonly customFields?:
    Partial<Record<BetterAuthModelKey, readonly BetterAuthCustomField[]>> | undefined
  readonly customModels?: readonly BetterAuthCustomModel[] | undefined
}

/**
 * Merge builder declarations with derived ones (`autoDeclare`).
 * Builder entries win per field/model; the derived remainder fills
 * the gaps, so a plugin the builder did not hand-declare still boots
 * — and a field the builder pinned stays pinned.
 */
export function mergeDeclarations(
  input: EngineDeclarations & {
    readonly autoDeclare?: boolean | undefined
    readonly options: Record<string, unknown>
  },
  autoDeclare: boolean
): {
  customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>>
  customModels: BetterAuthCustomModel[]
} {
  const builderFields = input.customFields ?? {}
  const builderModels = input.customModels ?? []
  if (!autoDeclare) {
    return {
      customFields: Object.fromEntries(
        Object.entries(builderFields).map(([model, fields]) => [model, [...(fields ?? [])]])
      ),
      customModels: builderModels.map((entry) => ({ ...entry, fields: [...entry.fields] })),
    }
  }
  const derived = deriveBetterAuthSchema(input.options)
  const customFields: Partial<Record<BetterAuthModelKey, BetterAuthCustomField[]>> = {}
  for (const model of new Set([
    ...Object.keys(derived.customFields),
    ...Object.keys(builderFields),
  ])) {
    const derivedFields = derived.customFields[model as BetterAuthModelKey] ?? []
    const builderOnes = builderFields[model as BetterAuthModelKey] ?? []
    const byName = new Map<string, BetterAuthCustomField>()
    for (const field of [...derivedFields, ...builderOnes]) {
      byName.set(field.name, field)
    }
    customFields[model as BetterAuthModelKey] = [...byName.values()]
  }
  const derivedModels = new Map(derived.customModels.map((entry) => [entry.model, entry]))
  const customModels: BetterAuthCustomModel[] = builderModels.map((entry) => ({
    ...entry,
    fields: [...entry.fields],
  }))
  for (const [model, entry] of derivedModels) {
    if (!customModels.some((declared) => declared.model === model)) {
      customModels.push({ ...entry, fields: [...entry.fields] })
    }
  }
  return { customFields, customModels }
}

/** Wiring contract, split out for tests: the BA version assertion. */
export function assertBetterAuthVersion(installedVersion: string | null, logger: LoggerPort): void {
  if (installedVersion === null) {
    logger.warn(
      'payload-auth-link: could not read the installed better-auth version; skipping the supported-version assertion'
    )
    return
  }
  assertSupportedVersion('better-auth', installedVersion, supportedBetterAuthBand)
}

export function createBetterAuthEngine<
  TOptions extends Omit<BetterAuthOptions, 'database'>,
  TPlugins extends readonly BetterAuthPlugin[] | undefined,
>(input: BetterAuthEngineInput<TOptions> & { options: { plugins?: TPlugins } }) {
  // Fail at wiring time on an unvalidated better-auth version, before
  // any collection write or schema validation (B3/B12).
  assertBetterAuthVersion(
    readInstalledVersion('better-auth', import.meta.url),
    input.logger ?? nullLogger()
  )
  const slugs: BetterAuthCollectionSlugs = resolveSlugs(defaultBetterAuthSlugs, input.slugs)
  const declared = mergeDeclarations(input, input.autoDeclare === true)
  const database = createPayloadDatabaseAdapter({
    getPayload: input.getPayload,
    slugs,
    schemaMap: input.schemaMap,
    idStrategy: input.idStrategy,
    depth: input.depth,
    customFields: declared.customFields,
    customModels: declared.customModels,
  })
  reportRiskyLinkingSettings(findRiskyLinkingSettings(input.options), {
    logger: input.logger ?? nullLogger(),
    strictLinking: input.strictLinking === true,
  })
  const emailAndPassword =
    input.options.emailAndPassword === undefined
      ? undefined
      : {
          requireEmailVerification: true,
          // CAP-14: a password reset revokes existing sessions by
          // default (BA's default keeps them); builders may opt out
          // explicitly and own the documented risk.
          revokeSessionsOnPasswordReset: true,
          ...input.options.emailAndPassword,
        }
  // CAP-14: translate BA database hooks into core IdentityEvents on
  // a bus the port exposes. Builder hooks run first and are preserved
  // verbatim for every model/phase we do not observe.
  const events = createIdentityEventBus(input.logger ?? nullLogger())
  const builderHooks = input.options.databaseHooks
  const databaseHooks: BetterAuthOptions['databaseHooks'] = {
    ...builderHooks,
    user: {
      ...builderHooks?.user,
      update: {
        ...builderHooks?.user?.update,
        after: async (user, context) => {
          await builderHooks?.user?.update?.after?.(user, context)
          await events.userUpdated(user)
        },
      },
      delete: {
        ...builderHooks?.user?.delete,
        after: async (user, context) => {
          await builderHooks?.user?.delete?.after?.(user, context)
          await events.userDeleted(user)
        },
      },
    },
    account: {
      ...builderHooks?.account,
      delete: {
        ...builderHooks?.account?.delete,
        after: async (account, context) => {
          await builderHooks?.account?.delete?.after?.(account, context)
          await events.accountDeleted(account)
        },
      },
    },
  }
  // CAP-12 guarantee: linking never rewrites `email`/`emailVerified`
  // in this composition. Installed Better Auth already excludes both
  // fields from `updateUserInfoOnLink`, but the engine forces the
  // setting off (the finding above warned, or threw under
  // `strictLinking`) so the guarantee cannot drift with upstream.
  const account =
    input.options.account?.accountLinking?.updateUserInfoOnLink === true
      ? {
          ...input.options.account,
          accountLinking: { ...input.options.account.accountLinking, updateUserInfoOnLink: false },
        }
      : input.options.account
  // The builder's `plugins` pass through verbatim inside
  // `input.options`: the engine never appends framework cookie plugins
  // (see the input docs), so there is no second guessable API beside
  // Better Auth's own `plugins` convention. `TPlugins` (bound on the
  // input type) keeps plugin endpoints inferred on `auth.api`.
  const auth = betterAuth({ ...input.options, database, emailAndPassword, account, databaseHooks })
  const sessionCookieNames = getBetterAuthSessionCookieNames(input.options)
  const sessionCookieClearOptions = getBetterAuthSessionCookieClearOptions(input.options)
  // `Auth` is invariant in its options, so the generically-typed instance
  // cannot convert to the port's structural type statically; the
  // shape-checked constructor closes the gap (see `port.ts`).
  // Capability honesty (PORT-2): capabilities are derived from the
  // plugins the builder actually installed (their `id`s), so the
  // port declares e.g. `'impersonation'` only with BA's admin
  // plugin — the sole producer of `session.impersonatedBy` — and
  // `'oauth'` additionally when core social providers are configured.
  const plugins: unknown = input.options.plugins
  const pluginIds: string[] = []
  if (Array.isArray(plugins)) {
    for (const plugin of plugins) {
      if (isRecord(plugin) && typeof plugin.id === 'string' && plugin.id !== '') {
        pluginIds.push(plugin.id)
      }
    }
  }
  const socialProviders: unknown = input.options.socialProviders
  const hasSocialOauth = isRecord(socialProviders) && Object.keys(socialProviders).length > 0
  const provider = createBetterAuthProviderFromUnknown(
    auth,
    sessionCookieNames,
    sessionCookieClearOptions,
    getBetterAuthLogoutCookieNames(input.options),
    {
      impersonation: pluginIds.includes('admin'),
      plugins: pluginIds,
      oauth: hasSocialOauth,
      events,
    }
  )
  const collections = createBetterAuthCollections({
    slugs: input.slugs,
    schemaMap: input.schemaMap,
    access: input.collectionsAccess,
    customFields: declared.customFields,
    customModels: declared.customModels,
  })
  return {
    auth,
    provider,
    collections,
    slugs,
    schemaMap: input.schemaMap ?? {},
    sessionCookieNames,
  }
}
