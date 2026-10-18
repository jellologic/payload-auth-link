import {
  assertCapabilities,
  assertNever,
  createProviderRegistry,
  defaultLinkingPolicy,
  consoleLogger,
  nullTracer,
  parseLinkingPolicy,
  parseRole,
  randomIds,
  sessionChannels,
  systemClock,
  validateStartupConfig,
  type ClockPort,
  type IdentityProviderPort,
  type IdPort,
  type LinkingPolicy,
  type LogFields,
  type LoggerPort,
  type ProviderId,
  type ProviderRegistry,
  type Role,
  type SessionChannel,
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
  /**
   * Roles that govern the auth system: write `roles`, `phone`,
   * `suspendedUntil` and `suspendReason` on users, read the
   * operator-facing fields, and reach the admin panel by default.
   * Defaults to `['admin']` when an `admin` role is configured;
   * required when it is not. Payload's Local API (overrideAccess)
   * is never restricted by this.
   */
  readonly roleManagerRoles?: readonly string[] | undefined
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
  /**
   * Canonical role → stored value map (issue #56). Roles stay canonical
   * inside the plugin (branded `Role`, `requireRoles`,
   * `requireMfaForRoles`); at the storage edge — field reads, writes,
   * and the injected select's options — values are translated, so a
   * payload-auth layout keeps storing e.g. `frontPlugin` unchanged.
   * Keys must be declared roles; two roles may not share a stored
   * value; unmapped roles store their canonical form.
   */
  readonly roleValues?: Readonly<Record<string, string>> | undefined
  /**
   * Admin panel surface (issue #55): `'provider'` swaps Payload's
   * local login view for the provider-backed one — email+password
   * through the provider's sign-in endpoint plus the break-glass
   * local fallback form (unlinked operator accounts only). The view
   * is registered as a Payload custom view; the import map must
   * include `@payload-auth-link/plugin/admin#ProviderLoginView` (the
   * doctor checks for it).
   */
  readonly admin?:
    | {
        readonly loginView?: 'provider' | undefined
        /**
         * The app's sign-in page the provider login view links
         * social-only accounts to. Defaults to `/sign-in`.
         */
        readonly signInPath?: string | undefined
        /**
         * App-relative mount of the cookie-transport provider's
         * routes (Better Auth's `basePath` as served by the app) —
         * the provider form posts to `${authBase}/sign-in/email`.
         * Defaults to `/api/auth`.
         */
        readonly authBase?: string | undefined
      }
    | undefined
  /**
   * Coexistence window (issue #51/#72): the same window you pass to
   * the provider ENGINE — `createBetterAuthEngine({ legacySessions })`
   * — which is the option that actually honors legacy payload-auth
   * session cookies (read-only) until the ISO `until` date. The
   * plugin cannot enable coexistence itself; this option exists to
   * ASSERT the engine's window at config time: wiring throws when
   * no engine declares one, when the two disagree, or when
   * `cookieNames` collides with the engine's current session cookie
   * names. Setting it without the engine input is a config error,
   * not a silent no-op.
   */
  readonly legacySessions?:
    | {
        readonly until: string
        readonly cookieNames: readonly string[]
      }
    | undefined
  /**
   * Server session creation gate (issue #54): controls
   * `authLinkServer(payload).createSessionFor`. `'dev-only'` (the
   * default) enables it ONLY on a development runtime (`NODE_ENV ===
   * 'development'` — production, test, staging, and unset all
   * refuse); `true` enables it everywhere; `false` disables it
   * everywhere. Reads, listings, revocations, and API-key
   * verification are never gated — only minting is.
   */
  readonly allowServerSessions?: 'dev-only' | true | false | undefined
  /**
   * What `req.user` carries (issue #57): `'projection'` (the default)
   * keeps the stable session projection `{ id, collection, email,
   * roles, … }`; `'document'` loads the FULL user document once per
   * request (the `req.context` memo) so access functions reading other
   * fields keep working unchanged. The security-relevant projected
   * fields stay authoritative either way: `roles` after the MFA
   * projection, `actor`/impersonation markers, suspension.
   */
  readonly reqUser?: 'projection' | 'document' | undefined
  /**
   * Which form `req.user.roles` carries (issue #56): `'canonical'`
   * (the default) always hands access functions the plugin's canonical
   * slugs; `'stored'` projects the values the database stores, so
   * access checks comparing against stored values (like `frontPlugin`)
   * keep working unchanged. The MFA gate and role governance always
   * operate on canonical roles regardless.
   */
  readonly projectRolesAs?: 'canonical' | 'stored' | undefined
  /**
   * Structured logger. Defaults to a console logger (refusals and
   * audit events are visible without configuration); pass
   * `nullLogger()` to opt out of all output.
   */
  readonly logger?: LoggerPort | undefined
  /**
   * Durable sink for impersonation audit events (CAP-8b), called in
   * addition to the logger. Wire it to a SIEM push, a database
   * insert, anything that survives log rotation — "audited" should
   * not mean "printed to stdout once".
   */
  readonly onAudit?: AuditSink | undefined
  /** Tracer. Defaults to a pass-through. */
  readonly tracer?: TracerPort | undefined
  /** Clock. Defaults to system time. */
  readonly clock?: ClockPort | undefined
  /** Id generator. Defaults to random UUIDs. */
  readonly ids?: IdPort | undefined
  /** Payload query depth for user reads. Defaults to `0`, always explicit. */
  readonly queryDepth?: number | undefined
  /**
   * Which verified claims may link a provider identity to a Payload
   * user (PORT-3). Defaults to `{ kind: 'verified-email' }`.
   * `'verified-email-or-phone'` (CAP-9) additionally links a
   * phone-only identity carrying a verified phone claim to an
   * EXISTING user whose stored phone matches — it never provisions,
   * and every registered provider must declare the `'phone'`
   * capability or wiring throws `UnsupportedCapabilityError`.
   */
  readonly linkingPolicy?: LinkingPolicy | undefined
  /** Phone field injected on the users collection (CAP-9). Defaults to `phone`. */
  readonly phoneField?: string | undefined
  /** Suspension-expiry field injected on users (CAP-7). Defaults to `suspendedUntil`. */
  readonly suspendedUntilField?: string | undefined
  /** Suspension-reason field injected on users (CAP-7). Defaults to `suspendReason`. */
  readonly suspendReasonField?: string | undefined
  /**
   * Session policies enforced by the plugin (CAP-6).
   * `requireMfaForRoles` withholds the listed roles from any session
   * whose assurance is not `mfa: true` (`'unknown'` never satisfies):
   * the strategy and session endpoint project the reduced role set
   * plus `mfaRequired: true`, so Payload access and app authorization
   * both see the step-up requirement. Every registered provider must
   * declare the `'mfa'` capability or wiring throws
   * `UnsupportedCapabilityError` (D4: Auth.js cannot satisfy this).
   */
  readonly policies?: { readonly requireMfaForRoles?: readonly string[] | undefined } | undefined
  /**
   * Payload-owned organizations (CAP-11, D1): when enabled the plugin
   * adds `organizations` + `memberships` collections and organization
   * endpoints. Slugs are overridable. Disabled by default — existing
   * sites gain no collections until they opt in.
   */
  readonly organizations?:
    | {
        readonly enabled: true
        readonly organizationsCollection?: string | undefined
        readonly membershipsCollection?: string | undefined
        /** Roles a membership can hold. Defaults to owner/admin/member. */
        readonly orgRoles?: readonly string[] | undefined
        /**
         * Enterprise SSO domain enforcement (CAP-15): registry ids of
         * providers whose sessions are SSO assertions (a BA SSO /
         * SAML-via-OAuth composition root). Sessions from these
         * providers link ONLY when the asserted email's domain is a
         * verified domain of some Payload organization — a
         * tenant-registered IdP can assert verified emails for
         * anyone, so the verified domain is the trust boundary.
         * Sessions from all other providers are unaffected.
         */
        readonly ssoProviders?: readonly string[] | undefined
      }
    | { readonly enabled?: false | undefined }
    | undefined
  /**
   * Session presentation channels verification admits (CAP-13a).
   * Defaults to `['cookie']`: a live provider session presented any
   * other way (`bearer`, `api-key`, `device`) is refused with a typed
   * `ChannelNotAdmittedError` (401), even though the credential itself
   * is valid. The Better Auth adapter reports `bearer` (BA's `bearer()`
   * plugin) and `api-key` (`@better-auth/api-key`) besides `cookie`;
   * the Auth.js adapter reports `cookie` only. Admitting `bearer` also
   * relaxes CSRF for bearer-presented requests ONLY (CAP-13b,
   * `passesCsrfForChannel`): an `Authorization: Bearer` header is not
   * an ambient credential, so the origin check is skipped for it;
   * cookie-presented requests keep requiring CSRF proof.
   */
  readonly admitChannels?: readonly SessionChannel[] | undefined
  /**
   * Provider-owned documents (GHSA-f4hj): a users document holding
   * linked provider identities authenticates through its provider —
   * local sign-in and the forgot/reset-password flow are refused for
   * it, because a local password would bypass the provider's MFA,
   * bans, rate limits, and revocation. The same holds for Payload API
   * keys (`auth.useAPIKey`): linking clears a key enabled before the
   * link, and a key on a linked document is refused (403). Defaults
   * to `false` (refuse).
   * Set `true` only for a migration window where documents must keep
   * working with both credentials; remove it once the migration
   * completes. Documents without linked identities (operator
   * accounts, pre-link imports) are unaffected either way.
   */
  readonly allowLocalCredentialsForLinkedDocs?: boolean | undefined
  /**
   * A HOST checkbox on the users collection that mirrors the
   * provider's email verification (issue #88) — e.g. payload-auth's
   * own `emailVerified` column, which import-mode apps keep. Unset
   * (the default), nothing is mirrored. When set, a provider event
   * reporting the linked user's CURRENT email as verified (a
   * post-import verification) sets this field `true`; the field must
   * exist on the users collection (wiring throws otherwise). The
   * plugin sets it `false` only together with the linking proof's
   * reset on an unproven email change (a self-service write that is
   * neither the provider resync nor a role manager's), as it does
   * Payload's `_verified`; any other un-verifying is the host's call.
   */
  readonly emailVerifiedField?: string | undefined
}

/** Injected governance/identity field names on the users collection. */
export type UserGovernanceFields = {
  readonly phoneField: string
  readonly suspendedUntilField: string
  readonly suspendReasonField: string
}

/** Validated organizations wiring (CAP-11); `null` when disabled. */
export type WiredOrganizations = {
  readonly organizationsCollection: string
  readonly membershipsCollection: string
  readonly orgRoles: readonly Role[]
  /** Provider registry ids under SSO domain enforcement (CAP-15). */
  readonly ssoProviders: readonly ProviderId[]
}

/** A single audit event: message plus structured fields. */
export type AuditEvent = { readonly message: string; readonly fields: LogFields }
/** Durable impersonation-audit sink; receives every audit event. */
export type AuditSink = (event: AuditEvent) => void

/** Validated, wired composition root for the plugin. */
export type WiredOptions = {
  readonly config: StartupConfig
  readonly registry: ProviderRegistry
  readonly logger: LoggerPort
  readonly tracer: TracerPort
  readonly clock: ClockPort
  readonly ids: IdPort
  readonly depth: number
  /** Validated linking policy (PORT-3); passed to `ensureLinkedUser`. */
  readonly linkingPolicy: LinkingPolicy
  /** Validated admitted session channels (CAP-13a); never empty. */
  readonly admitChannels: readonly SessionChannel[]
  /** Validated phone/suspension field names (CAP-7/CAP-9). */
  readonly userFields: UserGovernanceFields
  /** Roles withheld without MFA proof (CAP-6); empty means no policy. */
  readonly requireMfaForRoles: readonly Role[]
  /**
   * Canonical role → stored value (issue #56), complete over the
   * configured roles: unmapped roles map to themselves.
   */
  readonly roleValues: Readonly<Record<string, string>>
  /** The inverse of {@link WiredOptions.roleValues}: stored → canonical. */
  readonly roleValuesReverse: Readonly<Record<string, string>>
  /** Which form the session projection carries on `req.user.roles`. */
  readonly projectRolesAs: 'canonical' | 'stored'
  /** Whether `req.user` is the full document (issue #57). */
  readonly reqUser: 'projection' | 'document'
  /** Resolved server-session gate (issue #54), verbatim from options. */
  readonly allowServerSessions: 'dev-only' | true | false
  /** Whether the provider-backed admin login view is requested (#55). */
  readonly adminProviderLoginView: boolean
  /** The provider login view's app sign-in link (`admin.signInPath`). */
  readonly adminSignInPath: string
  /** The provider login view's provider route base (`admin.authBase`). */
  readonly adminAuthBase: string
  /** Validated coexistence window (issue #51), or `null`. */
  readonly legacySessions: {
    readonly until: string
    readonly cookieNames: readonly string[]
  } | null
  /**
   * Roles governing the auth system: gate
   * writes to injected governance fields, sensitive-field reads, and
   * the default admin-panel fallback. Never empty.
   */
  readonly roleManagerRoles: readonly Role[]
  /** Durable audit sink, or `null` when not configured. */
  readonly onAudit: AuditSink | null
  /** Organizations wiring (CAP-11), or `null` when not enabled. */
  readonly organizations: WiredOrganizations | null
  /**
   * Provider-owned documents (GHSA-f4hj): local sign-in and
   * forgot/reset-password are refused for documents holding linked
   * identities. `false` (the default) enforces it.
   */
  readonly allowLocalCredentialsForLinkedDocs: boolean
  /**
   * Host checkbox mirroring provider email verification (issue #88),
   * or `null` when not configured.
   */
  readonly emailVerifiedField: string | null
}

function fieldNameOption(value: string | undefined, fallback: string, label: string): string {
  if (value === undefined) {
    return fallback
  }
  if (typeof value !== 'string' || value === '' || value.length > 100) {
    throw new InvalidConfigError(
      `${label} must be a non-empty field name of at most 100 characters`
    )
  }
  return value
}

/** Parse + dedupe a role list option, failing fast on any bad entry. */
function parseRoleList(values: readonly string[] | undefined, label: string): Role[] {
  if (values === undefined) {
    return []
  }
  const roles: Role[] = []
  for (const value of values) {
    const parsed = parseRole(value)
    if (parsed.isErr()) {
      throw new InvalidConfigError(`${label} contains an invalid role: ${parsed.error.message}`)
    }
    if (!roles.includes(parsed.value)) {
      roles.push(parsed.value)
    }
  }
  return roles
}

/**
 * An app-relative path option rendered into the admin login view:
 * one leading `/`, never protocol-relative, no backslashes or
 * whitespace — the view uses it as a link and a fetch target.
 */
function validateAppPath(option: string, value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || /[\\\s]/.test(value)) {
    throw new InvalidConfigError(
      `${option} must be an app-relative path starting with a single "/", got ${JSON.stringify(value)}`
    )
  }
  return value
}

/**
 * Validate the coexistence window (issue #51): `until` must parse as
 * an ISO instant and the legacy cookie names must not collide with
 * the current session cookie names (the engine derives those from the
 * Better Auth options; here we only reject exact duplicates of the
 * names the builder also passed as current).
 */
function validateLegacySessions(
  raw:
    | {
        readonly until: string
        readonly cookieNames: readonly string[]
      }
    | undefined
): { readonly until: string; readonly cookieNames: readonly string[] } | null {
  if (raw === undefined) {
    return null
  }
  const parsed = new Date(raw.until)
  if (Number.isNaN(parsed.getTime())) {
    throw new InvalidConfigError(`legacySessions.until '${raw.until}' is not a valid date`)
  }
  const names = raw.cookieNames.map((name) => name.trim()).filter((name) => name !== '')
  if (names.length === 0) {
    throw new InvalidConfigError('legacySessions.cookieNames must not be empty')
  }
  return { until: parsed.toISOString(), cookieNames: names }
}

/**
 * The plugin's `legacySessions` option cannot enable coexistence —
 * the provider ENGINE's input is what honors legacy cookies (#72).
 * When the host declares the option, wiring therefore asserts the
 * engine's window: absent everywhere, or disagreeing on `until` or
 * `cookieNames`, all fail the build naming the fix. A legacy cookie
 * name equal to a current session cookie name is rejected too (it
 * would make the fast-path treat every request as carrying a session).
 * Engine-only configuration stays legal: the engine acts alone, no
 * assertion is demanded.
 */
function assertLegacySessionsConsistent(
  plugin: { readonly until: string; readonly cookieNames: readonly string[] } | null,
  providers: readonly IdentityProviderPort[]
): { readonly until: string; readonly cookieNames: readonly string[] } | null {
  if (plugin === null) {
    return null
  }
  const withWindow = providers.filter((provider) => provider.legacySessions !== undefined)
  if (withWindow.length === 0) {
    throw new InvalidConfigError(
      'legacySessions: no provider engine declares a coexistence window — the plugin option only cross-checks the window that acts. Pass the same window to your engine (createBetterAuthEngine({ legacySessions })) or remove the plugin option.'
    )
  }
  for (const provider of withWindow) {
    const engine = provider.legacySessions
    if (engine === undefined) {
      continue
    }
    // Compare instants and trimmed name SETS, not raw strings: the
    // plugin option is normalized on its way through validation (ISO
    // with milliseconds, trimmed names), the engine port carries the
    // host's raw strings — `'2099-01-01T00:00:00Z'` and
    // `'2099-01-01T00:00:00.000Z'` are the same window.
    const engineUntil = Date.parse(engine.until)
    const pluginUntil = Date.parse(plugin.until)
    const sameUntil = Number.isFinite(engineUntil) && engineUntil === pluginUntil
    const engineNames = engine.cookieNames.map((name) => name.trim())
    const sameNames =
      engineNames.length === plugin.cookieNames.length &&
      engineNames.every((name) => plugin.cookieNames.includes(name))
    if (!sameUntil || !sameNames) {
      throw new InvalidConfigError(
        `legacySessions: provider '${provider.id}' engine window (${engine.until}, [${engine.cookieNames.join(', ')}]) disagrees with the plugin option (${plugin.until}, [${plugin.cookieNames.join(', ')}]) — keep them identical, or set it on the engine only`
      )
    }
  }
  for (const provider of providers) {
    for (const name of plugin.cookieNames) {
      if (provider.sessionCookieNames.includes(name)) {
        throw new InvalidConfigError(
          `legacySessions.cookieNames: '${name}' is also a current session cookie name on provider '${provider.id}' — a legacy name must be a different cookie`
        )
      }
    }
  }
  return plugin
}

/**
 * Validate the role value map (issue #56): keys must be declared
 * roles, values non-empty, and the stored forms unique — two roles
 * sharing a stored value would make one silently grant the other. The
 * result is complete over the configured roles (unmapped roles store
 * their canonical form), so the storage edge never branches on
 * presence.
 */
function validateRoleValues(
  raw: Readonly<Record<string, string>> | undefined,
  roles: readonly Role[]
): Record<string, string> {
  const declared = new Set<string>(roles)
  const storedByCanonical: Record<string, string> = {}
  const seenStored = new Map<string, string>()
  for (const [canonical, stored] of Object.entries(raw ?? {})) {
    if (!declared.has(canonical)) {
      throw new InvalidConfigError(
        `roleValues has an entry for '${canonical}', which is not a declared role`
      )
    }
    if (stored === '') {
      throw new InvalidConfigError(`roleValues['${canonical}'] must not be empty`)
    }
    storedByCanonical[canonical] = stored
    const owner = seenStored.get(stored)
    if (owner !== undefined) {
      throw new InvalidConfigError(
        `roleValues: '${owner}' and '${canonical}' both store as '${stored}'; stored values must be unique`
      )
    }
    seenStored.set(stored, canonical)
  }
  for (const role of roles) {
    if (storedByCanonical[role] === undefined) {
      storedByCanonical[role] = role
    }
  }
  return storedByCanonical
}

/**
 * Validate `admitChannels` (CAP-13a). The default admits only
 * `cookie`. An explicitly empty list would refuse every session and
 * is far more likely a wiring mistake than intent, so it fails fast —
 * as do duplicates and (from JS callers) unknown channel strings.
 */
function validateAdmitChannels(
  raw: readonly SessionChannel[] | undefined
): readonly SessionChannel[] {
  if (raw === undefined) {
    return ['cookie']
  }
  if (raw.length === 0) {
    throw new InvalidConfigError("admitChannels must not be empty; omit it to admit only 'cookie'")
  }
  const seen = new Set<string>()
  for (const channel of raw) {
    if (!sessionChannels.includes(channel)) {
      throw new InvalidConfigError(
        `admitChannels contains an unknown channel ${JSON.stringify(channel)}; expected one of ${sessionChannels.join(', ')}`
      )
    }
    if (seen.has(channel)) {
      throw new InvalidConfigError(`admitChannels lists '${channel}' more than once`)
    }
    seen.add(channel)
  }
  return [...raw]
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
  let linkingPolicy: LinkingPolicy = defaultLinkingPolicy
  if (raw.linkingPolicy !== undefined) {
    const parsedPolicy = parseLinkingPolicy(raw.linkingPolicy)
    if (parsedPolicy.isErr()) {
      throw parsedPolicy.error
    }
    linkingPolicy = parsedPolicy.value
  }
  switch (linkingPolicy.kind) {
    case 'verified-email':
      break
    case 'verified-email-or-phone':
      // Capability gate (PORT-2): phone linking needs every registered
      // provider to declare `'phone'` — a provider that cannot produce
      // a phone claim makes the policy a lie, so wiring throws
      // `UnsupportedCapabilityError` naming it. CAP-9 supplies the
      // Payload phone field + `findByPhone` the branch resolves on.
      for (const provider of raw.providers) {
        assertCapabilities(provider, ['phone'])
      }
      break
    default:
      assertNever(linkingPolicy)
  }
  const userFields: UserGovernanceFields = {
    phoneField: fieldNameOption(raw.phoneField, 'phone', 'phoneField'),
    suspendedUntilField: fieldNameOption(
      raw.suspendedUntilField,
      'suspendedUntil',
      'suspendedUntilField'
    ),
    suspendReasonField: fieldNameOption(
      raw.suspendReasonField,
      'suspendReason',
      'suspendReasonField'
    ),
  }
  const takenFieldNames = new Set([
    validated.value.map.emailField,
    validated.value.map.rolesField,
    validated.value.map.identitiesField,
  ])
  for (const [label, name] of Object.entries(userFields)) {
    if (takenFieldNames.has(name)) {
      throw new InvalidConfigError(
        `${label} '${name}' collides with another users-collection field managed by the plugin`
      )
    }
    takenFieldNames.add(name)
  }
  const roleValues = validateRoleValues(raw.roleValues, validated.value.roles)
  const roleValuesReverse: Record<string, string> = {}
  for (const [canonical, stored] of Object.entries(roleValues)) {
    roleValuesReverse[stored] = canonical
  }
  const requireMfaForRoles = parseRoleList(
    raw.policies?.requireMfaForRoles,
    'policies.requireMfaForRoles'
  )
  for (const role of requireMfaForRoles) {
    if (!validated.value.roles.includes(role)) {
      throw new InvalidConfigError(
        `policies.requireMfaForRoles lists '${role}', which is not one of roles`
      )
    }
  }
  if (requireMfaForRoles.length > 0) {
    // CAP-6 capability gate: a policy no provider can satisfy must
    // fail at wiring, never silently withhold roles forever (D4).
    for (const provider of raw.providers) {
      assertCapabilities(provider, ['mfa'])
    }
  }
  // security hardening: the roles that govern the auth system.
  // Defaults to ['admin'] when an admin role exists; otherwise the
  // builder must name the managers — guessing one would mint either
  // an unmanaged system or a privilege nobody holds.
  let roleManagerRoles: readonly Role[]
  if (raw.roleManagerRoles === undefined) {
    const adminRole = validated.value.roles.find((role) => role === 'admin')
    if (adminRole === undefined) {
      throw new InvalidConfigError(
        'roleManagerRoles is required: no role named admin exists in roles, so ' +
          'payload-auth-link cannot guess who may assign roles, suspend users, or ' +
          'reach the admin panel. Pass roleManagerRoles: [...].'
      )
    }
    roleManagerRoles = [adminRole]
  } else {
    roleManagerRoles = parseRoleList(raw.roleManagerRoles, 'roleManagerRoles')
    if (roleManagerRoles.length === 0) {
      throw new InvalidConfigError('roleManagerRoles must not be empty')
    }
    for (const role of roleManagerRoles) {
      if (!validated.value.roles.includes(role)) {
        throw new InvalidConfigError(`roleManagerRoles lists '${role}', which is not one of roles`)
      }
    }
  }
  let organizations: WiredOrganizations | null = null
  if (raw.organizations?.enabled === true) {
    const orgsSlug = fieldNameOption(
      raw.organizations.organizationsCollection,
      'organizations',
      'organizations.organizationsCollection'
    )
    const membershipsSlug = fieldNameOption(
      raw.organizations.membershipsCollection,
      'memberships',
      'organizations.membershipsCollection'
    )
    if (
      orgsSlug === membershipsSlug ||
      orgsSlug === validated.value.map.usersCollection ||
      membershipsSlug === validated.value.map.usersCollection
    ) {
      throw new InvalidConfigError(
        'organization collection slugs must differ from each other and from the users collection'
      )
    }
    const orgRoles = parseRoleList(raw.organizations.orgRoles, 'organizations.orgRoles')
    const registeredIds = new Set(raw.providers.map((provider) => provider.id))
    const ssoProviders: ProviderId[] = []
    for (const rawId of raw.organizations.ssoProviders ?? []) {
      const match = raw.providers.find((provider) => provider.id === rawId)
      if (match === undefined || !registeredIds.has(match.id)) {
        throw new InvalidConfigError(
          `organizations.ssoProviders lists '${String(rawId)}', which is not a registered provider id`
        )
      }
      if (!ssoProviders.includes(match.id)) {
        ssoProviders.push(match.id)
      }
    }
    organizations = {
      organizationsCollection: orgsSlug,
      membershipsCollection: membershipsSlug,
      orgRoles:
        orgRoles.length > 0 ? orgRoles : parseRoleList(['owner', 'admin', 'member'], 'orgRoles'),
      ssoProviders,
    }
  }
  return {
    config: validated.value,
    registry,
    logger: raw.logger ?? consoleLogger(),
    tracer: raw.tracer ?? nullTracer(),
    clock: raw.clock ?? systemClock(),
    ids: raw.ids ?? randomIds(),
    depth,
    linkingPolicy,
    admitChannels: validateAdmitChannels(raw.admitChannels),
    userFields,
    requireMfaForRoles,
    roleValues,
    roleValuesReverse,
    projectRolesAs: raw.projectRolesAs === 'stored' ? ('stored' as const) : ('canonical' as const),
    reqUser: raw.reqUser === 'document' ? ('document' as const) : ('projection' as const),
    allowServerSessions:
      raw.allowServerSessions === true
        ? (true as const)
        : raw.allowServerSessions === false
          ? (false as const)
          : ('dev-only' as const),
    legacySessions: assertLegacySessionsConsistent(
      validateLegacySessions(raw.legacySessions),
      raw.providers
    ),
    adminProviderLoginView: raw.admin?.loginView === 'provider',
    adminSignInPath: validateAppPath('admin.signInPath', raw.admin?.signInPath ?? '/sign-in'),
    adminAuthBase: validateAppPath('admin.authBase', raw.admin?.authBase ?? '/api/auth'),
    roleManagerRoles,
    onAudit: raw.onAudit ?? null,
    organizations,
    allowLocalCredentialsForLinkedDocs: raw.allowLocalCredentialsForLinkedDocs === true,
    emailVerifiedField: emailVerifiedField(raw.emailVerifiedField, takenFieldNames),
  }
}

/**
 * Validate `emailVerifiedField` (issue #88): a plain field name that
 * must not be one of the fields the plugin itself manages.
 */
function emailVerifiedField(value: string | undefined, taken: ReadonlySet<string>): string | null {
  if (value === undefined) {
    return null
  }
  const name = fieldNameOption(value, '', 'emailVerifiedField')
  if (taken.has(name) || name === 'linkable' || name === 'linkableEmail') {
    throw new InvalidConfigError(
      `emailVerifiedField '${name}' collides with a users-collection field managed by the plugin`
    )
  }
  return name
}
