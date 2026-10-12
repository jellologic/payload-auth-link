import {
  createProviderRegistry,
  nullLogger,
  nullTracer,
  randomIds,
  systemClock,
  validateStartupConfig,
  type ClockPort,
  type IdentityProviderPort,
  type IdPort,
  type LoggerPort,
  type ProviderRegistry,
  type StartupConfig,
  type TracerPort,
} from '@payload-auth-link/core'
import { InvalidConfigError } from '@payload-auth-link/core'

/**
 * Raw plugin options from the site builder. Validated once at wiring
 * time; invalid options throw fail-fast at config time.
 */
export type AuthLinkPluginOptions = {
  /** Public origin of the site, e.g. `https://example.com`. */
  readonly baseUrl: string
  /**
   * @deprecated Ignored — nothing in the plugin signs or encrypts: session
   * integrity belongs to the identity provider (its own secret) and
   * Payload auth to Payload's `secret`. Kept optional so existing configs
   * still compile; remove it from your config.
   */
  readonly secret?: string | undefined
  /** All roles the site uses. */
  readonly roles: readonly string[]
  /** Role for newly created users. Must be one of `roles`. */
  readonly defaultRole: string
  /** Identity providers, fronted by their ports. At least one. */
  readonly providers: readonly IdentityProviderPort[]
  /** Payload collection holding users. Defaults to `users`. */
  readonly usersCollection?: string | undefined
  /** Email field on the users collection. Defaults to `email`. */
  readonly emailField?: string | undefined
  /** Roles field injected on the users collection. Defaults to `roles`. */
  readonly rolesField?: string | undefined
  /** Identities field injected on the users collection. Defaults to `identities`. */
  readonly identitiesField?: string | undefined
  /** Structured logger. Defaults to silent. */
  readonly logger?: LoggerPort | undefined
  /** Tracer. Defaults to a pass-through. */
  readonly tracer?: TracerPort | undefined
  /** Clock. Defaults to system time. */
  readonly clock?: ClockPort | undefined
  /** Id generator. Defaults to random UUIDs. */
  readonly ids?: IdPort | undefined
  /** Payload query depth for user reads. Defaults to `0`, always explicit. */
  readonly queryDepth?: number | undefined
}

/** Validated, wired composition root for the plugin. */
export type WiredOptions = {
  readonly config: StartupConfig
  readonly registry: ProviderRegistry
  readonly logger: LoggerPort
  readonly tracer: TracerPort
  readonly clock: ClockPort
  readonly ids: IdPort
  readonly depth: number
}

/**
 * Validate raw options and build the composition root. Throws
 * {@link InvalidConfigError} (or a registration error) on any problem:
 * misconfiguration must fail the build, never the first request.
 */
export function wireOptions(raw: AuthLinkPluginOptions): WiredOptions {
  const validated = validateStartupConfig({
    baseUrl: raw.baseUrl,
    roles: [...raw.roles],
    defaultRole: raw.defaultRole,
    providers: raw.providers.map((provider) => provider.id),
    map: {
      usersCollection: raw.usersCollection ?? 'users',
      emailField: raw.emailField ?? 'email',
      rolesField: raw.rolesField ?? 'roles',
      identitiesField: raw.identitiesField ?? 'identities',
    },
  })
  if (validated.isErr()) {
    throw validated.error
  }
  const registry = createProviderRegistry()
  for (const provider of raw.providers) {
    const registered = registry.register(provider)
    if (registered.isErr()) {
      throw registered.error
    }
  }
  const depth = raw.queryDepth ?? 0
  if (!Number.isInteger(depth) || depth < 0) {
    throw new InvalidConfigError(`queryDepth must be a non-negative integer, got ${String(depth)}`)
  }
  return {
    config: validated.value,
    registry,
    logger: raw.logger ?? nullLogger(),
    tracer: raw.tracer ?? nullTracer(),
    clock: raw.clock ?? systemClock(),
    ids: raw.ids ?? randomIds(),
    depth,
  }
}
