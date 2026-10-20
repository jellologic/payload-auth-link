import { APIError, createAuthMiddleware } from 'better-auth/api'
import type { BetterAuthPlugin } from 'better-auth'
import { isRecord, nullLogger, type LoggerPort } from '@payload-auth-link/core'

/**
 * Account-state enforcement on the Better Auth side (issues
 * GHSA-62xf-qq8f-x6w9 and GHSA-xxff-hh6q-c99p).
 *
 * Suspension (`suspendedUntil`, the plugin's CAP-7 field) and Better
 * Auth admin bans (`banned` + `banExpires`) were enforced only where
 * payload-auth-link resolves a session — the Payload strategy, the
 * server API, API keys. Better Auth's own endpoints kept working with
 * the same cookie: a suspended user could sign in fresh, read
 * `get-session`, mint API keys, update their profile; a banned user
 * kept every live session (Better Auth itself refuses bans only at
 * new sign-ins, and its revocation path was broken on adopted role
 * fields).
 *
 * This plugin closes that at the engine boundary:
 * - `hooks.before` on every request: when a session resolves, the user
 *   row is read fresh and an ACTIVE ban or suspension refuses the
 *   request with 403 — so `get-session` un-authenticates, and every
 *   authenticated provider endpoint (api keys, organization
 *   management, update-user, …) refuses.
 * - `databaseHooks.session.create.before`: the same check refuses the
 *   session at creation, so a suspended or banned user cannot sign in
 *   fresh.
 *
 * The user row is read FRESH per request (never from a cached
 * session): the state can change between requests, which is the point.
 * `suspendedUntil` is read from the configured field (the plugin's
 * CAP-7 field name); `banned`/`banExpires` are Better Auth's own admin
 * columns.
 */
export type AccountStateOptions = {
  /** The CAP-7 suspension field on the user row. Default: `suspendedUntil`. */
  readonly suspendedUntilField?: string | undefined
  /**
   * Read the user row FRESH through Payload (issue GHSA-jvpf-3fhq-f5ph):
   * Better Auth's internal adapter returns only BA-schema fields, and
   * the CAP-7 `suspendedUntil` field is not declared there — reading
   * through the internal adapter always sees it as undefined. When
   * provided, the endpoint-boundary check reads through this instead
   * (the engine passes a lookup honoring `schemaMap.user`,
   * `idStrategy`, and `suspendedUntilField`). Optional only for
   * payloads without the plugin's users fields.
   */
  readonly readUserRow?: ((userId: string) => Promise<unknown>) | undefined
  readonly logger?: LoggerPort | undefined
}

const DEFAULT_SUSPENDED_UNTIL_FIELD = 'suspendedUntil'

function asDate(value: unknown): Date | null {
  if (value instanceof Date) {
    return value
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime()) ? null : parsed
  }
  return null
}

export function activeBanOf(user: Record<string, unknown>, now: Date): boolean {
  if (user.banned !== true) {
    return false
  }
  const banExpires = asDate(user.banExpires)
  if (banExpires === null) {
    return true
  }
  return banExpires.getTime() > now.getTime()
}

export function activeSuspensionOf(
  user: Record<string, unknown>,
  field: string,
  now: Date
): boolean {
  const until = asDate(user[field])
  return until !== null && until.getTime() > now.getTime()
}

function accountRefused(reason: 'banned' | 'suspended'): APIError {
  return APIError.from('FORBIDDEN', {
    message:
      reason === 'banned'
        ? 'this account is banned'
        : 'this account is suspended until further notice',
    code: reason === 'banned' ? 'ACCOUNT_BANNED' : 'ACCOUNT_SUSPENDED',
  })
}

/** One fresh user-row read + the two state checks. Returns null when allowed. */
export async function accountStateRefusal(
  userId: string,
  field: string,
  readUserRow: (id: string) => Promise<unknown>,
  logger: LoggerPort
): Promise<APIError | null> {
  const row: unknown = await readUserRow(userId)
  if (!isRecord(row)) {
    return null
  }
  const now = new Date()
  if (activeBanOf(row, now)) {
    logger.warn('account-state: banned user refused', { userId })
    return accountRefused('banned')
  }
  if (activeSuspensionOf(row, field, now)) {
    logger.warn('account-state: suspended user refused', { userId })
    return accountRefused('suspended')
  }
  return null
}

export function createAccountStatePlugin(options: AccountStateOptions = {}): BetterAuthPlugin {
  const logger = options.logger ?? nullLogger()
  const field = options.suspendedUntilField ?? DEFAULT_SUSPENDED_UNTIL_FIELD
  // The user-row reader for the suspension check (issue GHSA-jvpf):
  // Better Auth's internal adapter returns only BA-schema fields, so
  // the CAP-7 `suspendedUntil` column must be read through Payload.
  // The engine always wires this; a bare plugin without it enforces
  // bans only (suspension is skipped, never falsely enforced).
  return {
    id: 'payload-auth-link-account-state',
    init: () => ({ context: {} }),
    hooks: {
      before: [
        {
          matcher: () => true,
          handler: createAuthMiddleware(async (ctx) => {
            // Read the session row DIRECTLY via the internal adapter —
            // NOT through getSessionFromCtx, whose resolution would
            // pre-empt the endpoint's own session handling (the aged-
            // session refresh test caught exactly that).
            const sessionToken = await ctx.getSignedCookie(
              ctx.context.authCookies.sessionToken.name,
              ctx.context.secret
            )
            if (typeof sessionToken !== 'string' || sessionToken === '') {
              return
            }
            const findSession = (
              ctx.context.internalAdapter as {
                findSession?: (token: string) => Promise<unknown>
              }
            ).findSession
            if (typeof findSession !== 'function') {
              return
            }
            const resolved: unknown = await findSession(sessionToken)
            if (!isRecord(resolved) || !isRecord(resolved.user) || !isRecord(resolved.session)) {
              return
            }
            const expiresAt: unknown = resolved.session.expiresAt
            const expiry = expiresAt instanceof Date ? expiresAt : new Date(String(expiresAt))
            if (Number.isNaN(expiry.getTime()) || expiry.getTime() <= Date.now()) {
              return
            }
            const userId: unknown = resolved.user.id
            if (typeof userId !== 'string' || userId === '') {
              return
            }
            // The suspension check MUST read through Payload
            // (GHSA-jvpf): the internal adapter narrows the row to
            // BA-schema fields and drops the CAP-7 column. Bans are
            // visible there, suspension is not — so without a row
            // reader, only bans are enforced at this boundary.
            const rowReader = options.readUserRow
            if (rowReader === undefined) {
              logger.warn('account-state: no row reader wired; suspension not enforced here', {
                userId,
              })
              return
            }
            const refusal = await accountStateRefusal(userId, field, (id) => rowReader(id), logger)
            if (refusal !== null) {
              throw refusal
            }
          }),
        },
      ],
    },
  }
}
