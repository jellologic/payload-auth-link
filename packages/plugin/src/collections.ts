import {
  InvalidConfigError,
  isRecord,
  isSuspendedAt,
  parsePhoneNumber,
  toDate,
} from '@payload-auth-link/core'
import type {
  Access,
  ArrayField,
  AuthStrategy,
  CheckboxField,
  CollectionAfterChangeHook,
  CollectionBeforeChangeHook,
  CollectionBeforeOperationHook,
  CollectionConfig,
  DateField,
  Field,
  FieldAccess,
  FieldAccessArgs,
  GlobalBeforeOperationHook,
  SelectField,
  TextField,
  PayloadRequest,
  Where,
} from 'payload'
import { APIError } from 'payload'
import { isImpersonating } from './access.js'
import type { WiredOptions } from './options.js'
import { normalizeUserEmailHook } from './hooks.js'
import { strategyName } from './strategy.js'

type CollectionAccess = NonNullable<CollectionConfig['access']>
type AdminAccess = NonNullable<CollectionAccess['admin']>

/**
 * Roles on the request's user (the session projection or a full
 * Payload user document); empty when there is no usable shape.
 */
function userRoles(user: unknown): readonly string[] {
  if (!isRecord(user)) {
    return []
  }
  const roles = user.roles
  if (!Array.isArray(roles)) {
    return []
  }
  return roles.filter((role): role is string => typeof role === 'string')
}

/**
 * May this request govern the auth system — write roles/governance
 * fields, read operator-facing fields, reach the admin panel by
 * default? Fails closed: no user, no roles
 * array, or no intersection with the configured manager roles means
 * no.
 */
export function isRoleManager(req: FieldAccessArgs['req'], wired: WiredOptions): boolean {
  const managers = new Set<string>(wired.roleManagerRoles)
  return userRoles(req.user).some((role) => managers.has(role))
}

/** Is this request reading/writing its own user document? */
function isSelfDoc(req: FieldAccessArgs['req'], id: FieldAccessArgs['id']): boolean {
  const user = req.user
  return isRecord(user) && id !== undefined && String(user.id) === String(id)
}

/**
 * Default impersonation policy on the users collection (CAP-8b /
 * D5): the admin panel is denied while impersonating. A builder
 * `access.admin` still decides every non-impersonated request; the
 * fallback is the role-manager roles — never "any signed-in user",
 * which made every linked user an admin-panel user
 *.
 */
function denyAdminWhileImpersonating(
  existing: AdminAccess | undefined,
  wired: WiredOptions
): AdminAccess {
  return async ({ req }) => {
    if (isImpersonating(req)) {
      return false
    }
    if (existing !== undefined) {
      return existing({ req })
    }
    return isRoleManager(req, wired)
  }
}

/**
 * Governance writes (roles, phone, suspension) on injected fields:
 * role-manager roles only, with the impersonation deny on top. The
 * Local API (overrideAccess) never runs field access, so the
 * plugin's own engine-driven writes are unaffected.
 * (security hardening: Payload's field-access default allowed any
 * authenticated user to write roles — a self-service privilege
 * escalation.)
 */
function governedWrite(wired: WiredOptions): { create: FieldAccess; update: FieldAccess } {
  const decide = ({ req }: FieldAccessArgs) => !isImpersonating(req) && isRoleManager(req, wired)
  return { create: decide, update: decide }
}

/** Read access: role managers, or the document's own user. */
function readSelfOrManagers(wired: WiredOptions): FieldAccess {
  return ({ req, id }) => isRoleManager(req, wired) || isSelfDoc(req, id)
}

/** Read access: role managers only (operator-facing data). */
function readManagersOnly(wired: WiredOptions): FieldAccess {
  return ({ req }) => isRoleManager(req, wired)
}

/**
 * `req.context` key the plugin sets on engine-driven Local-API creates
 * (JIT provisioning, credentials registration): proof the document was
 * created by payload-auth-link itself, from a verified provider
 * identity.
 */
export const linkableCreateMarker = 'payload-auth-link:create'

/**
 * Fill collection-level `create`/`read` defaults on the users
 * collection (GHSA-98hq-hh6v-2p2r): Payload's own defaults give every
 * authenticated user create and list access to every user document,
 * which enabled pre-account hijack through JIT email linking and user
 * enumeration. Gaps are filled per key; a host-declared function is
 * never overridden.
 */
function withDefaultUserAccess(
  access: CollectionConfig['access'],
  wired: WiredOptions
): CollectionAccess {
  const filled: CollectionAccess = { ...access }
  if (filled.create === undefined) {
    const decide = ({ req }: { req: Parameters<typeof isImpersonating>[0] }) => {
      return !isImpersonating(req) && isRoleManager(req, wired)
    }
    filled.create = decide
  }
  if (filled.read === undefined) {
    // Managers see every user; everyone else is constrained to their
    // own document (list and find alike) — user enumeration was the
    // targeting step of the pre-account hijack.
    filled.read = ({ req }) => {
      if (isRoleManager(req, wired)) {
        return true
      }
      const user = req.user
      if (isRecord(user) && typeof user.email === 'string' && user.email !== '') {
        return { [wired.config.map.emailField]: { equals: user.email } }
      }
      return false
    }
  }
  if (filled.update === undefined) {
    // Payload's default lets any signed-in user update ANY user —
    // with JIT sign-up that is anyone. Managers update everyone;
    // everyone else only their own document.
    filled.update = ({ req }) => {
      if (isImpersonating(req)) {
        return false
      }
      if (isRoleManager(req, wired)) {
        return true
      }
      const user = req.user
      if (isRecord(user) && (typeof user.id === 'string' || typeof user.id === 'number')) {
        return { id: { equals: user.id } }
      }
      return false
    }
  }
  if (filled.delete === undefined) {
    filled.delete = ({ req }) => !isImpersonating(req) && isRoleManager(req, wired)
  }
  if (filled.unlock === undefined) {
    // Payload's default lets any signed-in user unlock any account,
    // which undoes the brute-force lockout for whoever is guessing.
    filled.unlock = ({ req }) => !isImpersonating(req) && isRoleManager(req, wired)
  }
  filled.admin = denyAdminWhileImpersonating(filled.admin, wired)
  return filled
}

/**
 * The JIT-linking proof marker (GHSA-98hq-hh6v-2p2r): a document is
 * linked by email only when something has proven it owns that email.
 * The plugin sets the marker on engine-driven creates (verified
 * provider identity) and on role-manager creates (admin/import
 * workflows); documents created any other way — or created outside
 * the plugin — start unproven and are never JIT-linked until a role
 * manager marks them. Plain-user creates are refused at the
 * collection level, so the flag cannot be self-granted.
 */
function linkableMarkerHook(wired: WiredOptions): CollectionBeforeChangeHook {
  return ({ collection, operation, data, originalDoc, req }) => {
    if (operation === 'update') {
      resetProofOnEmailChange(wired, { collection, data, originalDoc, req })
      return
    }
    if (operation !== 'create') {
      return
    }
    const proven =
      isRoleManager(req, wired) ||
      (isRecord(req.context) && req.context[linkableCreateMarker] === true)
    if (proven) {
      data.linkable = true
      // Proof is bound to the email: an email change that is not the
      // plugin's own provider-email sync invalidates it automatically
      // (the guard compares the two on every lookup).
      if (typeof data.email === 'string' && data.email !== '') {
        data.linkableEmail = data.email
      }
    } else if (data.linkable === undefined) {
      data.linkable = false
    }
  }
}

/**
 * Email-ownership proof never survives an unproven email change: when
 * a document's email changes in a write that is neither the plugin's
 * provider-email resync (which re-grants the proof for the new,
 * provider-verified address in the same write) nor a role manager's,
 * the `linkable` proof and its `linkableEmail` are cleared — and, on
 * hosts with `auth.verify`, Payload's `_verified` flag too, which
 * Payload itself keeps across email changes. The document is then
 * unproven until a role manager re-grants the proof.
 *
 * "Re-granted in the same write" is safe to honor: field access lets
 * only role managers (and trusted `overrideAccess` Local-API callers,
 * such as the resync) write `linkable`/`linkableEmail` at all, so a
 * self-service write never carries them this far.
 */
function resetProofOnEmailChange(
  wired: WiredOptions,
  args: {
    readonly collection: { readonly auth?: unknown }
    readonly data: Record<string, unknown>
    readonly originalDoc: unknown
    readonly req: PayloadRequest
  }
): void {
  const { data, originalDoc, req } = args
  const emailField = wired.config.map.emailField
  const next = data[emailField]
  const previous = isRecord(originalDoc) ? originalDoc[emailField] : undefined
  if (
    typeof next !== 'string' ||
    typeof previous !== 'string' ||
    next.toLowerCase() === previous.toLowerCase()
  ) {
    return
  }
  const regranted =
    data.linkable === true &&
    typeof data.linkableEmail === 'string' &&
    data.linkableEmail.toLowerCase() === next.toLowerCase()
  if (regranted || isRoleManager(req, wired)) {
    return
  }
  data.linkable = false
  data.linkableEmail = null
  const auth = args.collection.auth
  if (isRecord(auth) && auth.verify !== undefined && auth.verify !== false) {
    data._verified = false
  }
  const userId =
    isRecord(originalDoc) &&
    (typeof originalDoc.id === 'string' || typeof originalDoc.id === 'number')
      ? String(originalDoc.id)
      : ''
  wired.logger.info('email changed outside the provider resync; linking proof reset', { userId })
}

function linkableField(wired: WiredOptions): CheckboxField {
  return {
    name: 'linkable',
    type: 'checkbox',
    defaultValue: false,
    // The JIT-linking proof: writing it is a role-manager decision
    // (it grants linking to whatever email the document carries);
    // users never read it.
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description:
        'Set when payload-auth-link (or a role manager) proved this document owns its email. JIT linking refuses documents without it.',
    },
  }
}

/**
 * The email the `linkable` proof was granted for (GHSA-8524). The
 * proof holds only while the document's email still equals it — a
 * self-service email change therefore invalidates linking until a
 * role manager re-proves the new address. The plugin's own
 * provider-email resync keeps the proof in step (repository
 * `setEmail`).
 */
function linkableEmailField(wired: WiredOptions): TextField {
  return {
    name: 'linkableEmail',
    type: 'text',
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description:
        'The email the linkable proof was granted for. JIT linking requires it to match the document email.',
    },
  }
}

/**
 * Email changes over REST on documents with linked identities are
 * role-manager-only (GHSA-8524): a self-service email change on a
 * linked document would move a proven, linkable identity surface onto
 * an unverified address. Documents without linked identities are the
 * owner's to rename (nothing links to them by email yet). The
 * plugin's provider-email resync runs with `overrideAccess` and is
 * unaffected.
 */
function emailUpdateAccess(wired: WiredOptions): FieldAccess {
  return ({ req, doc, id }) => {
    if (isImpersonating(req)) {
      return false
    }
    if (isRoleManager(req, wired)) {
      return true
    }
    // A non-manager only ever changes their OWN email: a host whose
    // collection-level update is broader must not let one user re-point
    // another's address (and then reset that account's password).
    const target = id ?? (isRecord(doc) ? (doc.id as FieldAccessArgs['id']) : undefined)
    if (!isSelfDoc(req, target)) {
      return false
    }
    const identities = isRecord(doc) ? doc[wired.config.map.identitiesField] : undefined
    const hasIdentities = Array.isArray(identities) && identities.length > 0
    return !hasIdentities
  }
}

/**
 * Self-service local passwords are fail-closed (GHSA-8524): a
 * provider-provisioned user must not be able to mint a Payload local
 * credential for their document, which would bypass Better Auth's
 * MFA, bans, rate limits, and verification. Non-manager password
 * writes are stripped in beforeOperation (before Payload's update
 * reads `data.password`); role managers may set passwords, and hosts
 * who declare their own password field access keep it.
 */
function passwordGuardHook(
  wired: WiredOptions
): NonNullable<CollectionConfig['hooks']>['beforeOperation'] extends (infer F)[] | undefined
  ? F
  : never {
  return ({ args, operation, req }) => {
    if (operation !== 'update') {
      return args
    }
    const data = isRecord(args) ? args.data : undefined
    if (!isRecord(data) || data.password === undefined) {
      return args
    }
    if (isImpersonating(req) || !isRoleManager(req, wired)) {
      const stripped = { ...data }
      delete stripped.password
      return { ...args, data: stripped }
    }
    return args
  }
}

function emailField(wired: WiredOptions): Field {
  return {
    name: wired.config.map.emailField,
    type: 'email',
    access: { update: emailUpdateAccess(wired) },
  }
}

/**
 * Is the document currently suspended (CAP-7)? Shared by the login
 * gate and the request-time constraints.
 */
function suspensionActive(doc: unknown, wired: WiredOptions): boolean {
  if (!isRecord(doc)) {
    return false
  }
  const suspendedUntil = toDate(doc.suspendedUntil)
  return isSuspendedAt(suspendedUntil, wired.clock.now())
}

/**
 * Local sign-in refusal for suspended users (GHSA-f4hj): Payload's
 * local strategy never consulted the plugin, so a suspended user with
 * a local password could still sign in. Payload's `beforeLogin` only
 * refuses when a hook THROWS (a falsy return keeps the login), so the
 * refusal is a typed `APIError`. `resetPassword` runs `beforeLogin`
 * too, which refuses the reset flow for suspended users with it.
 */
function accountControlsLoginHook(
  wired: WiredOptions
): NonNullable<CollectionConfig['hooks']>['beforeLogin'] extends (infer F)[] | undefined
  ? F
  : never {
  return ({ user }) => {
    if (suspensionActive(user, wired)) {
      throw new APIError('Account suspended', 401)
    }
    // Provider-owned documents (GHSA-f4hj): once a document holds
    // linked provider identities, the provider owns its credential —
    // a local password would bypass the provider's MFA, bans, rate
    // limits, and revocation. Local sign-in is refused unless the
    // host opted in. Documents without identities (operator
    // accounts, pre-link imports) are unaffected.
    if (wired.allowLocalCredentialsForLinkedDocs) {
      return
    }
    const identities: unknown = isRecord(user) ? user[wired.config.map.identitiesField] : undefined
    if (Array.isArray(identities) && identities.length > 0) {
      throw new APIError(
        'Local sign-in is unavailable for provider-linked accounts; use your identity provider',
        403
      )
    }
  }
}

/**
 * Self-service password issuance for provider-linked documents is
 * refused (GHSA-f4hj): Payload's forgot/reset-password flow runs with
 * `overrideAccess`, so the 0.6.0 password-write strip never saw it,
 * and a provider-provisioned user could mint a local credential for
 * their own document from their own inbox. The gate resolves the
 * target document (by email for `forgotPassword`, by the reset token
 * for `resetPassword` — Payload matches the stored token directly)
 * and refuses documents holding linked identities. Hosts who want the
 * previous behaviour set `allowLocalCredentialsForLinkedDocs`.
 *
 * `resetPassword` additionally refuses SUSPENDED documents (401)
 * here, whatever the opt-out: Payload's reset writes the new password
 * and clears the sessions BEFORE it runs `beforeLogin`, and where that
 * write is not rolled back (adapters without transactions) the
 * `beforeLogin` refusal came too late — the "refused" reset had
 * rotated the credential (issue #86). The lookup runs inside the
 * operation's transaction (`req`).
 */
function passwordIssueGuardHook(wired: WiredOptions): CollectionBeforeOperationHook {
  const usersCollection = wired.config.map.usersCollection
  return async ({ args, operation, req }) => {
    if (operation !== 'forgotPassword' && operation !== 'resetPassword') {
      return args
    }
    const optedOut = wired.allowLocalCredentialsForLinkedDocs
    if (optedOut && operation === 'forgotPassword') {
      return args
    }
    const data: unknown = isRecord(args) ? args.data : undefined
    const email = isRecord(data) && typeof data.email === 'string' ? data.email : undefined
    const token = isRecord(data) && typeof data.token === 'string' ? data.token : undefined
    let where: Where | undefined
    if (operation === 'forgotPassword' && email !== undefined && email !== '') {
      where = { [wired.config.map.emailField]: { equals: email } }
    }
    if (operation === 'resetPassword' && token !== undefined && token !== '') {
      where = { resetPasswordToken: { equals: token } }
    }
    if (where === undefined) {
      return args
    }
    const found = await req.payload.find({
      collection: usersCollection,
      where,
      limit: 1,
      depth: 0,
      pagination: false,
      overrideAccess: true,
      req,
    })
    const doc: unknown = (found as { docs?: unknown[] }).docs?.[0]
    if (!isRecord(doc)) {
      // Unknown target: an existing document is not being attacked —
      // Payload's own response (enumeration-neutral) stands.
      return args
    }
    if (operation === 'resetPassword' && suspensionActive(doc, wired)) {
      throw new APIError('Account suspended', 401)
    }
    if (optedOut) {
      return args
    }
    const identities: unknown = doc[wired.config.map.identitiesField]
    if (!Array.isArray(identities) || identities.length === 0) {
      return args
    }
    const docId = typeof doc.id === 'string' || typeof doc.id === 'number' ? String(doc.id) : ''
    wired.logger.warn('local password reset refused: document holds linked identities', {
      userId: docId,
      operation,
    })
    throw new APIError(
      'Password reset is unavailable for provider-linked accounts; use your identity provider',
      403
    )
  }
}

/**
 * Fresh, per-request account status for the request's user. The local
 * JWT carries a login-time snapshot; suspension must be seen the
 * moment an operator sets it, so the document is re-read (one read
 * per request, memoized on `req.context` — every collection's gate
 * shares the result).
 */
const ACCOUNT_STATUS_KEY = 'payload-auth-link:account-status'
/**
 * In-flight sentinel: the status read is a users-collection read, so
 * it re-enters the very gates that ask for it. An inner application
 * seeing the sentinel skips (the outer computation always concludes
 * and stores the result — or throws, ending the request).
 */
const ACCOUNT_STATUS_INFLIGHT = 'payload-auth-link:account-status-inflight'

type AccountStatus = {
  readonly suspended: boolean
  readonly failed?: boolean
  /** The document holds linked provider identities (provider-owned). */
  readonly linked?: boolean
}

/** Payload's local JWT strategy name (`_strategy` on `req.user`). */
const localJwtStrategyName = 'local-jwt'

type AccountDecision = 'ok' | 'suspended' | 'failed' | 'provider-owned'

async function requestAccountStatus(
  req: PayloadRequest,
  wired: WiredOptions
): Promise<AccountStatus> {
  const memo: Record<string, unknown> | undefined = isRecord(req.context) ? req.context : undefined
  if (memo !== undefined) {
    const cached = memo[ACCOUNT_STATUS_KEY]
    if (isRecord(cached) && typeof cached.suspended === 'boolean') {
      return cached as AccountStatus
    }
    if (memo[ACCOUNT_STATUS_INFLIGHT] === true) {
      // Re-entrant status read (the check itself reads the users
      // collection): let it through — the outer computation owns the
      // decision for this request.
      return { suspended: false }
    }
  }
  // Not a request pipeline (access functions invoked directly with a
  // fabricated request carry no payload): there is nothing to govern.
  if (
    !isRecord(req.payload) ||
    typeof (req.payload as Record<string, unknown>).findByID !== 'function'
  ) {
    return { suspended: false }
  }
  const user = req.user
  let status: AccountStatus
  if (memo !== undefined) {
    memo[ACCOUNT_STATUS_INFLIGHT] = true
  }
  try {
    const doc: unknown = await req.payload.findByID({
      collection: wired.config.map.usersCollection,
      id: String(isRecord(user) ? user.id : ''),
      depth: 0,
      overrideAccess: true,
    })
    const identities: unknown = isRecord(doc) ? doc[wired.config.map.identitiesField] : undefined
    status = {
      suspended: suspensionActive(doc, wired),
      linked: Array.isArray(identities) && identities.length > 0,
    }
  } catch (cause) {
    // Fail closed: an unreadable account state must never wave a
    // request through. The same storage failure fails the operation
    // itself, so this only changes who reports it.
    wired.logger.error('account status check failed; refusing the request', { cause })
    status = { suspended: false, failed: true }
  } finally {
    if (memo !== undefined) {
      memo[ACCOUNT_STATUS_INFLIGHT] = false
    }
  }
  if (memo !== undefined) {
    memo[ACCOUNT_STATUS_KEY] = status
  }
  return status
}

/**
 * Account controls for the request's user, evaluated once per request
 * and shared by the operation gate and the access wrappers: fresh
 * suspension state (the local JWT carries a login-time snapshot) plus
 * the MFA projection for non-provider sessions. Returns the decision;
 * callers translate it (throw / refuse).
 */
async function applyAccountControls(
  req: PayloadRequest,
  wired: WiredOptions,
  gated: ReadonlySet<string>
): Promise<AccountDecision> {
  const user = req.user
  // Local API calls without a request user (the plugin's own engine
  // paths run `overrideAccess` with no `req.user`) are unaffected.
  if (!isRecord(user)) {
    return 'ok'
  }
  // Only the plugin's users collection is governed; Payload's
  // strategies stamp the source collection on the resolved user
  // (`local-jwt`, `api-key`), as does the auth-link strategy.
  if (user.collection !== wired.config.map.usersCollection) {
    return 'ok'
  }
  const status = await requestAccountStatus(req, wired)
  if (status.failed) {
    return 'failed'
  }
  if (status.suspended) {
    return 'suspended'
  }
  // Provider-owned documents hold no local session (GHSA-f4hj
  // default): local sign-in is refused for them, so a local JWT on a
  // linked document can only predate the link — issued to whoever
  // held the document before the provider's verified owner arrived.
  // Linking clears Payload's `sessions` array (repository
  // `linkIdentity`); this gate covers hosts without `useSessions`,
  // where a JWT is otherwise valid until it expires.
  if (
    !wired.allowLocalCredentialsForLinkedDocs &&
    status.linked === true &&
    user._strategy === localJwtStrategyName
  ) {
    return 'provider-owned'
  }
  if (user._strategy !== strategyName) {
    // Issue #57: `reqUser: 'document'` also shapes LOCAL sessions
    // (Payload's local JWT and API keys carry the full document but not
    // the projection's assurance) — load the document once per request
    // through the same memo the strategy uses.
    if (wired.reqUser === 'document' && typeof user.id !== 'undefined') {
      const memo = isRecord(req.context) ? (req.context as Record<string, unknown>) : undefined
      const memoKey = 'payloadAuthLink:reqUserDocument'
      let document: unknown = memo?.[memoKey]
      if (document === undefined && typeof req.payload?.findByID === 'function') {
        document = await req.payload.findByID({
          collection: wired.config.map.usersCollection,
          id: user.id,
          depth: wired.depth,
          overrideAccess: true,
        })
        if (memo !== undefined) {
          memo[memoKey] = document
        }
      }
      if (isRecord(document)) {
        // The reshaped user is Payload's own document with the request's
        // resolved identity fields on top; the assignment target is
        // Payload's typed user.
        const shaped: Record<string, unknown> = {
          ...document,
          id: user.id,
          email: typeof user.email === 'string' ? user.email : document.email,
          roles: Array.isArray(user.roles) ? user.roles : document.roles,
          collection: user.collection,
          _strategy: user._strategy,
        }
        req.user = shaped as typeof req.user
      }
    }
  }
  if (gated.size === 0 || user._strategy === strategyName) {
    return 'ok'
  }
  if (Array.isArray(user.roles)) {
    user.roles = user.roles.filter(
      (role): role is string => typeof role === 'string' && !gated.has(role)
    )
  }
  return 'ok'
}

function throwOnAccountDecision(decision: AccountDecision): void {
  if (decision === 'provider-owned') {
    throw new APIError(
      'Local sessions are unavailable for provider-linked accounts; sign in with your identity provider',
      401
    )
  }
  if (decision === 'failed') {
    throw new APIError('Account status could not be verified', 503)
  }
  if (decision === 'suspended') {
    throw new APIError('Account suspended', 401)
  }
}

/**
 * Request-time account controls on EVERY strategy (GHSA-f4hj): the
 * `auth-link` strategy enforces suspension and the MFA projection at
 * verification, but Payload's local JWT and API-key strategies resolve
 * `req.user` without consulting the plugin — and `beforeLogin` does
 * nothing for a token minted before the control applied. This hook
 * runs in `beforeOperation` (which Payload evaluates BEFORE access
 * control) on every collection and global, so a suspended user's next
 * request is refused outright and `requireMfaForRoles` roles are
 * withheld from local sessions (which have no MFA proof — fail
 * closed) before any access check reads them. Provider sessions carry
 * the strategy's own projection and keep their proof.
 */
export function accountControlsGateHook(wired: WiredOptions): CollectionBeforeOperationHook {
  const gated = new Set<string>(wired.requireMfaForRoles)
  return async ({ req }) => {
    throwOnAccountDecision(await applyAccountControls(req, wired, gated))
  }
}

/**
 * The same account controls for Payload globals: a suspended user's
 * local JWT must not read or write global data either. Shares the
 * per-request status memo with the collection gate.
 */
export function accountControlsGlobalGateHook(wired: WiredOptions): GlobalBeforeOperationHook {
  const gated = new Set<string>(wired.requireMfaForRoles)
  return async ({ req }) => {
    throwOnAccountDecision(await applyAccountControls(req, wired, gated))
  }
}

/**
 * Access-layer belt for the users collection (GHSA-f4hj): the
 * `/access` map and `docAccess` run access functions WITHOUT any
 * collection operation, so the operation gate never sees them. Every
 * users-collection access decision therefore applies the account
 * controls first — a suspended account holds no grant, and the MFA
 * projection lands before manager checks read the roles (making
 * `canAccessAdmin` truthful for policy roles held locally). Host
 * collections keep their own access functions (their operations are
 * gated above; only their permission MAP can overstate for a local
 * session, which no operation then honors).
 */
function withAccountControlledAccess(
  access: CollectionAccess | undefined,
  wired: WiredOptions
): CollectionAccess {
  const gated = new Set<string>(wired.requireMfaForRoles)
  const controlled: CollectionAccess = { ...access }
  // Per-key access types are narrower intersections (Payload allows
  // fn arrays for some keys); the belt stores supertype `Access` fns
  // through a widened record.
  const slots = controlled as Record<string, Access | undefined>
  const guard =
    (existing: Access): Access =>
    async (args) => {
      const decision = await applyAccountControls(args.req, wired, gated)
      // An access decision refuses; it never throws (the /access map
      // and docAccess must render for the caller, grantless).
      if (decision === 'failed') {
        throw new APIError('Account status could not be verified', 503)
      }
      if (decision === 'suspended' || decision === 'provider-owned') {
        return false
      }
      return existing(args)
    }
  for (const key of ['create', 'read', 'update', 'delete', 'admin', 'unlock'] as const) {
    const existing = access?.[key]
    if (existing !== undefined) {
      slots[key] = guard(existing)
      continue
    }
    // Unfilled mutation keys: install Payload's own default
    // (`Boolean(user)`) under the belt, so the permission map cannot
    // overstate for a suspended session. `read`/`create`/`admin` are
    // always filled by `withDefaultUserAccess` before this runs.
    if (key === 'update' || key === 'delete' || key === 'unlock') {
      slots[key] = guard(({ req }) => Boolean(req.user))
    }
  }
  return controlled
}

function rolesField(wired: WiredOptions): SelectField {
  return {
    name: wired.config.map.rolesField,
    type: 'select',
    hasMany: true,
    // Role changes are denied while impersonating (CAP-8b / D5) and
    // restricted to the role-manager roles:
    // field access is the surgical deny — an impersonated update can
    // still touch other fields but can never write roles, and a
    // plain user can never write roles at all. Users still read
    // their own roles (the session projection carries them anyway).
    access: {
      ...governedWrite(wired),
      read: readSelfOrManagers(wired),
    },
    // Required rejects `[]` for hasMany selects (Payload's select
    // validation treats an empty array as missing), so emptied roles
    // can no longer persist through the API or admin UI.
    required: true,
    // The select stores role VALUES (issue #56): options carry the
    // stored form (labelled with the canonical role), so admin edits
    // round-trip without a database change.
    options: wired.config.roles.map((role) => ({
      label: role,
      value: wired.roleValues[role] ?? role,
    })),
    defaultValue: [wired.roleValues[wired.config.defaultRole] ?? wired.config.defaultRole],
    admin: {
      description: 'Managed by payload-auth-link. At least one role is required.',
    },
  }
}

function identitiesField(wired: WiredOptions): ArrayField {
  return {
    name: wired.config.map.identitiesField,
    type: 'array',
    // Engine-managed data: writes are denied at
    // field level for every REST/admin caller — linking happens
    // through the plugin's Local-API paths only — and reads are
    // role-manager only: identity rows carry provider user ids and
    // emails that are not the reader's to enumerate.
    access: {
      create: () => false,
      update: () => false,
      read: readManagersOnly(wired),
    },
    admin: {
      readOnly: true,
      description: 'Provider identities linked by payload-auth-link. Managed automatically.',
      components: {
        RowLabel: {
          path: '@payload-auth-link/plugin/admin',
          exportName: 'IdentityRowLabel',
        },
      },
    },
    fields: [
      { name: 'providerId', type: 'text', required: true },
      { name: 'providerUserId', type: 'text', required: true },
      { name: 'email', type: 'email', required: true },
      { name: 'linkedAt', type: 'date', required: true },
    ],
  }
}

function phoneField(wired: WiredOptions): TextField {
  return {
    name: wired.userFields.phoneField,
    type: 'text',
    index: true,
    // A phone value is a linking identifier (CAP-9): if users could
    // write it, they could aim a verified-phone claim at an account
    // they do not own, so writes are role-manager only, like the
    // other governance fields. Claim-driven
    // writes flow through the Local API and are unaffected.
    access: { ...governedWrite(wired), read: readSelfOrManagers(wired) },
    // E.164 only: this value is a linking identifier (CAP-9), not a
    // display string. Empty clears it.
    validate: (value: unknown) => {
      if (value === undefined || value === null || value === '') {
        return true
      }
      const parsed = parsePhoneNumber(value)
      return parsed.isOk() ? true : parsed.error.message
    },
    admin: {
      description:
        'Verified E.164 phone (e.g. +14155550132). Synced from a verified provider phone claim; used only to link phone sign-ins to this existing user.',
    },
  }
}

function suspendedUntilField(wired: WiredOptions): DateField {
  return {
    name: wired.userFields.suspendedUntilField,
    type: 'date',
    index: true,
    // Governance write + operator-facing read:
    // whether a user is suspended and until when is not their read.
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description:
        'Suspended until this instant (payload-auth-link CAP-7). While in the future, every session for this user is refused — provider sessions, local sign-in, and any local JWT or API key already held; clear it or let it lapse to readmit.',
      date: { pickerAppearance: 'dayAndTime' },
    },
  }
}

function suspendReasonField(wired: WiredOptions): TextField {
  return {
    name: wired.userFields.suspendReasonField,
    type: 'text',
    // Operator-facing: never exposed to the
    // user or clients, matching the docs — managers read, managers
    // write, and the deny-while-impersonating rule stays on top.
    access: { ...governedWrite(wired), read: readManagersOnly(wired) },
    admin: {
      description: 'Operator-facing suspension reason. Never exposed to the user or clients.',
    },
  }
}

/**
 * Best-effort provider revocation on suspension (CAP-7): when a write
 * puts `suspendedUntil` into the future (and it was not already
 * there), every linked identity's provider sessions are revoked via
 * `revokeUserSessions` where the adapter supports it. Failures are
 * logged, never thrown — the Payload-side verify gate refuses the
 * user regardless, so revocation is defense in depth, and a provider
 * outage must not roll back an operator's suspension.
 */
function suspendRevokeHook(wired: WiredOptions): CollectionAfterChangeHook {
  return async ({ doc, previousDoc }) => {
    const field = wired.userFields.suspendedUntilField
    const now = wired.clock.now()
    const next = isRecord(doc) ? toDate(doc[field]) : null
    if (!isSuspendedAt(next, now)) {
      return
    }
    const prev = isRecord(previousDoc) ? toDate(previousDoc[field]) : null
    if (prev !== null && next !== null && prev.getTime() === next.getTime()) {
      return
    }
    const identities: unknown = isRecord(doc) ? doc[wired.config.map.identitiesField] : undefined
    if (Array.isArray(identities)) {
      for (const row of identities) {
        if (!isRecord(row)) {
          continue
        }
        const { providerId, providerUserId } = row
        if (typeof providerId !== 'string' || typeof providerUserId !== 'string') {
          continue
        }
        const parsedId =
          typeof providerId === 'string'
            ? wired.registry.ids().find((id) => id === providerId)
            : undefined
        if (parsedId === undefined) {
          continue
        }
        const required = wired.registry.require(parsedId)
        if (required.isErr() || required.value.revokeUserSessions === undefined) {
          continue
        }
        const revoked = await required.value.revokeUserSessions(providerUserId)
        if (revoked.isErr()) {
          wired.logger.error('suspend: provider session revoke failed', {
            providerId,
            cause: revoked.error.cause ?? revoked.error,
          })
        } else {
          wired.logger.info('suspend: provider sessions revoked', { providerId })
        }
      }
    }
    // No return: the hook never modifies the document.
  }
}

/** Field name when the field variant has one (`collapsible` has none). */
export function fieldName(field: Field): string | undefined {
  return 'name' in field ? field.name : undefined
}

function withStrategy(
  auth: CollectionConfig['auth'],
  strategy: AuthStrategy
): Exclude<CollectionConfig['auth'], undefined> {
  if (auth === undefined || auth === false) {
    return { strategies: [strategy] }
  }
  if (auth === true) {
    return { strategies: [strategy] }
  }
  const strategies = auth.strategies ?? []
  if (strategies.some((candidate) => candidate.name === strategyName)) {
    return auth
  }
  return { ...auth, strategies: [...strategies, strategy] }
}

function createUsersCollection(wired: WiredOptions, strategy: AuthStrategy): CollectionConfig {
  const { map } = wired.config
  return {
    slug: map.usersCollection,
    access: withAccountControlledAccess(withDefaultUserAccess(undefined, wired), wired),
    admin: {
      useAsTitle: map.emailField,
      defaultColumns: [map.emailField, map.rolesField],
      description: 'Users managed by payload-auth-link.',
    },
    auth: {
      disableLocalStrategy: { enableFields: true, optionalPassword: true },
      strategies: [strategy],
    },
    fields: [
      emailField(wired),
      rolesField(wired),
      identitiesField(wired),
      phoneField(wired),
      suspendedUntilField(wired),
      suspendReasonField(wired),
      linkableField(wired),
      linkableEmailField(wired),
    ],
    hooks: {
      beforeValidate: [normalizeUserEmailHook(map)],
      beforeOperation: [
        passwordGuardHook(wired),
        passwordIssueGuardHook(wired),
        accountControlsGateHook(wired),
      ],
      beforeLogin: [accountControlsLoginHook(wired)],
      beforeChange: [linkableMarkerHook(wired)],
      afterChange: [suspendRevokeHook(wired)],
    },
  }
}

/**
 * Ensure the users collection exists with our fields, strategy, and hooks.
 * Pure config transform: never mutates its input, never overwrites existing
 * hooks or strategies, and throws {@link InvalidConfigError} on field-name
 * collisions instead of silently skipping them.
 */
/**
 * Adopt a compatible host `roles` field instead of throwing (a
 * migration path from plugins that made the Payload user table BE the
 * provider's user table — those apps already carry a role select).
 * Compatible means: Payload `select`, `hasMany: true`, and an options
 * list that covers every configured role (extra options are the
 * host's business and stay). Adoption imposes the plugin's
 * governance — required, role-manager write access, self/manager
 * read, the default — and leaves the host's options, labels, and
 * admin presentation untouched.
 */
function adoptRolesField(host: Field, wired: WiredOptions): SelectField {
  const slug = wired.config.map.usersCollection
  const name = wired.config.map.rolesField
  const fail = (detail: string): never => {
    throw new InvalidConfigError(
      `users collection '${slug}' has a '${name}' field this plugin cannot adopt: ${detail} ` +
        `Make it a multi-select covering every configured role, or rename it and let ` +
        `the plugin inject '${name}'.`
    )
  }
  if (host.type !== 'select') {
    fail(`it is a '${host.type}' field, not a select`)
  }
  const select = host as SelectField
  if (select.hasMany !== true) {
    fail('it is a single-select (hasMany is not true)')
  }
  // Coverage is checked against the STORED forms (issue #56): the host
  // select stores values, and the plugin's map is the only translation
  // layer.
  const configured = new Set<string>(
    wired.config.roles.map((role) => wired.roleValues[role] ?? role)
  )
  const declared = new Set<string>(
    (select.options ?? [])
      .map((option) => (typeof option === 'string' ? option : option.value))
      .filter((value): value is string => typeof value === 'string')
  )
  const missing = [...configured].filter((role) => !declared.has(role))
  if (missing.length > 0) {
    fail(
      `its options are missing the configured role(s) ${missing.map((r) => `'${r}'`).join(', ')}`
    )
  }
  return {
    ...select,
    access: { ...governedWrite(wired), read: readSelfOrManagers(wired) },
    required: true,
    ...(select.defaultValue === undefined ? { defaultValue: [wired.config.defaultRole] } : {}),
  }
}

export function applyUsersCollection(
  collections: readonly CollectionConfig[] | undefined,
  wired: WiredOptions,
  strategy: AuthStrategy
): CollectionConfig[] {
  const slug = wired.config.map.usersCollection
  const existing = collections?.find((collection) => collection.slug === slug)
  const mirror = wired.emailVerifiedField
  if (mirror !== null) {
    // The verified-email mirror (issue #88) is a HOST field the plugin
    // writes; naming one the host does not declare is a config error,
    // never a silent no-op.
    const declared = existing?.fields.find((candidate) => fieldName(candidate) === mirror)
    if (declared === undefined || declared.type !== 'checkbox') {
      throw new InvalidConfigError(
        `emailVerifiedField '${mirror}' must name a checkbox field declared on the '${slug}' collection`
      )
    }
  }
  if (!existing) {
    return [...(collections ?? []), createUsersCollection(wired, strategy)]
  }
  const rolesName = wired.config.map.rolesField
  const hostRolesField = existing.fields.find((candidate) => fieldName(candidate) === rolesName)
  // An existing roles-shaped select is ADOPTED (migration from
  // plugins whose users table carried the role column); anything else
  // colliding with the plugin's names still fails fast with the
  // remediation.
  const roles: Field =
    hostRolesField === undefined ? rolesField(wired) : adoptRolesField(hostRolesField, wired)
  const identities = identitiesField(wired)
  const governance = [
    phoneField(wired),
    suspendedUntilField(wired),
    suspendReasonField(wired),
    linkableField(wired),
    linkableEmailField(wired),
  ]
  // Email gap-fill (GHSA-8524): when the host's users collection has
  // no email field in its config (Payload injects the base field at
  // sanitize time), the plugin injects one carrying the fail-closed
  // update access; when the host declares one, its access wins and
  // only an absent update access is gap-filled.
  const hostEmailField = existing.fields.find(
    (candidate) => fieldName(candidate) === wired.config.map.emailField
  )
  let email: Field
  if (hostEmailField === undefined) {
    email = emailField(wired)
  } else if (
    isRecord((hostEmailField as { access?: Record<string, unknown> }).access) &&
    (hostEmailField as { access?: Record<string, unknown> }).access?.update !== undefined
  ) {
    email = hostEmailField
  } else {
    // Deep-merge at sanitize keeps the base email field's required/
    // hooks; only the access here is ours. The union spread needs the
    // narrow cast back to the field type.
    email = {
      ...hostEmailField,
      access: { update: emailUpdateAccess(wired) },
    } as typeof hostEmailField
  }
  for (const field of [identities, ...governance]) {
    const collision = existing.fields.find((candidate) => fieldName(candidate) === field.name)
    if (collision) {
      const remediation =
        field.name === wired.config.map.identitiesField
          ? 'rename it or point the collection map elsewhere (the identities array is engine-managed and cannot be adopted)'
          : 'rename it or point the collection map elsewhere'
      throw new InvalidConfigError(
        `users collection '${slug}' already has a '${field.name}' field; ${remediation}`
      )
    }
  }
  const beforeValidate = existing.hooks?.beforeValidate ?? []
  const afterChange = existing.hooks?.afterChange ?? []
  // Replace the host's roles/email fields in place when present (the
  // adopted/governed variants); append whatever is missing. Payload
  // rejects duplicate field names, so injection must never follow a
  // failed replacement.
  const replaced = existing.fields.map((field) =>
    field === hostRolesField ? roles : field === hostEmailField ? email : field
  )
  const fields = [
    ...replaced,
    ...(hostRolesField === undefined ? [roles] : []),
    ...(hostEmailField === undefined ? [email] : []),
    identities,
    ...governance,
  ]
  return (collections ?? []).map((collection) =>
    collection.slug === slug
      ? {
          ...existing,
          access: withAccountControlledAccess(withDefaultUserAccess(existing.access, wired), wired),
          auth: withStrategy(existing.auth, strategy),
          fields,
          hooks: {
            ...existing.hooks,
            beforeValidate: [...beforeValidate, normalizeUserEmailHook(wired.config.map)],
            beforeOperation: [
              ...(existing.hooks?.beforeOperation ?? []),
              passwordGuardHook(wired),
              passwordIssueGuardHook(wired),
              accountControlsGateHook(wired),
            ],
            beforeLogin: [...(existing.hooks?.beforeLogin ?? []), accountControlsLoginHook(wired)],
            beforeChange: [...(existing.hooks?.beforeChange ?? []), linkableMarkerHook(wired)],
            afterChange: [...afterChange, suspendRevokeHook(wired)],
          },
        }
      : collection
  )
}
