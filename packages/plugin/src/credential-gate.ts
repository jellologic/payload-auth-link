import { isRecord, isSuspendedAt, toDate } from '@payload-auth-link/core'
import type { CollectionAfterReadHook, Payload, PayloadRequest } from 'payload'
import { APIError } from 'payload'
import type { WiredOptions } from './options.js'

/**
 * Authentication-time account controls for Payload's OWN credentials
 * on the users collection (GHSA-mjvh-7vmj-pg2p).
 *
 * Payload resolves `req.user` once per request, by running the
 * registered auth strategies in order: every collection's custom
 * `auth.strategies` first, then its API-key strategy, then the shared
 * local-JWT strategy last. A strategy can only return a user or pass;
 * nothing in Payload's config lets one strategy veto a later one, and
 * the built-in strategies never consult the plugin. A suspended
 * user's API key, a key re-enabled on a provider-linked document, or
 * a pre-link local JWT on a host without `useSessions` therefore
 * authenticated everywhere the per-collection gates do not reach:
 * upload file routes, custom endpoints, `payload.auth()`,
 * `payload-preferences`, and `/access` on other collections.
 *
 * The veto lives where the built-in strategies load the user: both
 * read the users collection through the Local API with the request's
 * `req` and `overrideAccess` (JWT: `findByID` of the token's `id`;
 * API key: `find` on `apiKeyIndex`), so the users collection's
 * `afterRead` hooks run on the very document they are about to
 * authenticate — fresh from the database. The plugin's own strategy
 * (always registered before them on the users collection) arms the
 * gate for the credential this request presents; the gate's
 * `afterRead` hook refuses that one lookup when the account is dead,
 * and the built-in strategy, which treats a failed lookup as "no
 * user", resolves `req.user = null`. Every surface downstream then
 * sees an anonymous request.
 *
 * Only Payload-supported extension points are used (a collection
 * auth strategy, a collection hook, `req.context`); Payload's
 * strategies are never wrapped or replaced.
 */
export const LOCAL_CREDENTIAL_GATE_KEY = 'payload-auth-link:local-credential-gate'

/** Payload's local JWT strategy name (`_strategy` on `req.user`). */
export const localJwtStrategyName = 'local-jwt'
/** Payload's API-key strategy name (`_strategy` on `req.user`). */
export const apiKeyStrategyName = 'api-key'

type LocalStrategy = typeof localJwtStrategyName | typeof apiKeyStrategyName

/**
 * The armed gate for one request: the users-collection credential the
 * request presents, consumed by the one lookup that authenticates it.
 */
type GateMarker = {
  /** Document id a users-collection JWT names (signature unchecked). */
  jwtUserId: string | null
  /** A users-collection API key is presented. */
  apiKey: boolean
}

function isGateMarker(value: unknown): value is GateMarker {
  return (
    isRecord(value) &&
    typeof value.apiKey === 'boolean' &&
    (value.jwtUserId === null || typeof value.jwtUserId === 'string')
  )
}

/**
 * Is the document currently suspended (CAP-7)? Reads the CONFIGURED
 * suspension field (`suspendedUntilField`), so a renamed field is
 * enforced like the default.
 */
export function suspensionActive(doc: unknown, wired: WiredOptions): boolean {
  if (!isRecord(doc)) {
    return false
  }
  const suspendedUntil = toDate(doc[wired.userFields.suspendedUntilField])
  return isSuspendedAt(suspendedUntil, wired.clock.now())
}

/** Does the document hold linked provider identities (provider-owned)? */
export function holdsLinkedIdentities(doc: unknown, wired: WiredOptions): boolean {
  const identities: unknown = isRecord(doc) ? doc[wired.config.map.identitiesField] : undefined
  return Array.isArray(identities) && identities.length > 0
}

/** Why a Payload local credential may not authenticate this document. */
export type LocalCredentialRefusal = 'suspended' | 'provider-owned' | 'provider-owned-api-key'

/**
 * The account-control decision for a Payload local credential (local
 * JWT or API key) on a users-collection document: suspension refuses
 * every credential; a provider-linked document refuses local ones
 * unless the host opted into `allowLocalCredentialsForLinkedDocs`
 * (GHSA-f4hj / GHSA-x45w). `null` means the credential may stand.
 */
export function localCredentialRefusal(
  doc: unknown,
  strategy: LocalStrategy,
  wired: WiredOptions
): LocalCredentialRefusal | null {
  if (suspensionActive(doc, wired)) {
    return 'suspended'
  }
  if (wired.allowLocalCredentialsForLinkedDocs || !holdsLinkedIdentities(doc, wired)) {
    return null
  }
  return strategy === apiKeyStrategyName ? 'provider-owned-api-key' : 'provider-owned'
}

/** Decode a JWT's claims WITHOUT verifying it (Payload verifies). */
function unverifiedClaims(token: string): Record<string, unknown> | null {
  const segment = token.split('.')[1]
  if (segment === undefined || segment === '') {
    return null
  }
  try {
    const base64 = segment.replace(/-/g, '+').replace(/_/g, '/')
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    const claims: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return isRecord(claims) ? claims : null
  } catch {
    // Not a JWT (a provider bearer token, garbage): Payload's own
    // strategy refuses it too, so there is nothing to gate.
    return null
  }
}

function cookieValue(headers: Headers, name: string): string | null {
  for (const part of (headers.get('cookie') ?? '').split(';')) {
    const separator = part.indexOf('=')
    if (separator !== -1 && part.slice(0, separator).trim() === name) {
      const value = part.slice(separator + 1).trim()
      return value === '' ? null : value
    }
  }
  return null
}

/**
 * The token Payload's local-JWT strategy would read, in the host's
 * `auth.jwtOrder`. Payload additionally applies its CSRF rules to the
 * cookie channel; over-reading here only arms a gate for a lookup
 * that then never happens.
 */
function presentedJwt(headers: Headers, payload: Payload): string | null {
  const authorization = headers.get('authorization') ?? ''
  for (const channel of payload.config.auth.jwtOrder) {
    if (channel === 'Bearer' && authorization.startsWith('Bearer ')) {
      return authorization.slice('Bearer '.length)
    }
    if (channel === 'JWT' && authorization.startsWith('JWT ')) {
      return authorization.slice('JWT '.length)
    }
    if (channel === 'cookie') {
      const cookie = cookieValue(headers, `${payload.config.cookiePrefix}-token`)
      if (cookie !== null) {
        return cookie
      }
    }
  }
  return null
}

/**
 * Arm the gate for the users-collection credential this request
 * presents to Payload's built-in strategies. Called by the plugin's
 * strategy whenever it resolves no user — the only case in which
 * Payload goes on to try its own strategies.
 */
export function armLocalCredentialGate(
  headers: Headers,
  payload: Payload,
  req: PayloadRequest | undefined,
  wired: WiredOptions
): void {
  if (req === undefined || !isRecord(req.context)) {
    return
  }
  const context: Record<string, unknown> = req.context
  const slug = wired.config.map.usersCollection
  const auth: unknown = payload.collections[slug]?.config.auth
  if (!isRecord(auth)) {
    return
  }
  const authorization = headers.get('authorization') ?? ''
  const apiKey = auth.useAPIKey === true && authorization.startsWith(`${slug} API-Key `)
  let jwtUserId: string | null = null
  if (auth.disableLocalStrategy === undefined || auth.disableLocalStrategy === false) {
    const token = presentedJwt(headers, payload)
    const claims = token === null ? null : unverifiedClaims(token)
    if (
      claims !== null &&
      claims.collection === slug &&
      (typeof claims.id === 'string' || typeof claims.id === 'number')
    ) {
      jwtUserId = String(claims.id)
    }
  }
  if (!apiKey && jwtUserId === null) {
    disarmLocalCredentialGate(req)
    return
  }
  const marker: GateMarker = { jwtUserId, apiKey }
  context[LOCAL_CREDENTIAL_GATE_KEY] = marker
}

/**
 * Drop any armed gate: the plugin's strategy authenticated the request
 * itself, so Payload's built-in strategies never run for it.
 */
export function disarmLocalCredentialGate(req: PayloadRequest | undefined): void {
  if (req !== undefined && isRecord(req.context)) {
    const context: Record<string, unknown> = req.context
    delete context[LOCAL_CREDENTIAL_GATE_KEY]
  }
}

/** Does a `where` constraint name the field anywhere in its tree? */
function whereMentions(where: unknown, field: string): boolean {
  if (Array.isArray(where)) {
    return where.some((entry) => whereMentions(entry, field))
  }
  if (!isRecord(where)) {
    return false
  }
  return Object.entries(where).some(
    ([key, value]) =>
      key === field || ((key === 'and' || key === 'or') && whereMentions(value, field))
  )
}

const refusalMessages: Readonly<Record<LocalCredentialRefusal, string>> = {
  suspended: 'Account suspended',
  'provider-owned':
    'Local sessions are unavailable for provider-linked accounts; sign in with your identity provider',
  'provider-owned-api-key': 'API keys are unavailable for provider-linked accounts',
}

/**
 * The gate's veto: the users-collection `afterRead` hook that refuses
 * the armed credential's lookup when the account is dead. It matches
 * exactly the built-in strategies' reads — `overrideAccess`, the
 * JWT's `findByID` of the named document, or the API key's `find` on
 * `apiKeyIndex` — and is consumed by the first one, so every other
 * read of the request is untouched. The thrown error never reaches
 * the client: Payload's strategies treat it as "no user".
 */
export function localCredentialGateHook(wired: WiredOptions): CollectionAfterReadHook {
  return ({ doc: read, findMany, overrideAccess, query, req }) => {
    // Payload types the hook's document as `any`; it is read as data.
    const doc: unknown = read
    const context: unknown = req.context
    const marker: unknown = isRecord(context) ? context[LOCAL_CREDENTIAL_GATE_KEY] : undefined
    if (!isGateMarker(marker) || overrideAccess !== true || !isRecord(doc)) {
      return doc
    }
    const rawId: unknown = doc.id
    const id = typeof rawId === 'string' || typeof rawId === 'number' ? String(rawId) : null
    let strategy: LocalStrategy
    if (findMany !== true && marker.jwtUserId !== null && id === marker.jwtUserId) {
      strategy = localJwtStrategyName
      marker.jwtUserId = null
    } else if (findMany === true && marker.apiKey && whereMentions(query, 'apiKeyIndex')) {
      strategy = apiKeyStrategyName
      marker.apiKey = false
    } else {
      return doc
    }
    const refusal = localCredentialRefusal(doc, strategy, wired)
    if (refusal === null) {
      return doc
    }
    wired.logger.warn('local credential refused at authentication', {
      ...(id === null ? {} : { userId: id }),
      strategy,
      reason: refusal,
    })
    throw new APIError(refusalMessages[refusal], 401)
  }
}
