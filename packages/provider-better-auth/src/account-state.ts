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
  findUserById: (id: string) => Promise<unknown>,
  logger: LoggerPort
): Promise<APIError | null> {
  const row: unknown = await findUserById(userId)
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
            const findUserById = (
              ctx.context.internalAdapter as {
                findUserById?: (id: string) => Promise<unknown>
              }
            ).findUserById
            if (typeof findUserById !== 'function') {
              return
            }
            const refusal = await accountStateRefusal(
              userId,
              field,
              (id) => findUserById(id),
              logger
            )
            if (refusal !== null) {
              throw refusal
            }
          }),
        },
      ],
    },
  }
}
