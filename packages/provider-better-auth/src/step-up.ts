import { APIError, isAPIError } from 'better-auth/api'
import type { AuthMethod, LoggerPort } from '@payload-auth-link/core'
import { ResultAsync } from 'neverthrow'

/**
 * Second-factor step-up guard (GHSA-38wx-69j6-cgm7). Better Auth's
 * `twoFactor` plugin counts failed verifications and locks the account
 * only on the SIGN-IN challenge path; a verification presented on an
 * EXISTING session (a step-up) is neither counted nor refused while
 * the account is locked. Since the session-provenance plugin relabels
 * a stepped-up session `two-factor`, an uncounted step-up would make
 * the MFA gate brute-forceable. This module closes that gap with Better
 * Auth's OWN per-user counter — the `twoFactor` row's
 * `failedVerificationCount` / `lockedUntil`, honouring the plugin's
 * `accountLockout` options — so sign-in and step-up share one budget
 * and one lock. It also decides whether a step-up may count as MFA
 * proof at all (see {@link StepUpAssessment}).
 */

/** The Better Auth `twoFactor` model the counter lives on. */
const TWO_FACTOR_MODEL = 'twoFactor'

/** The OTP verification route: its code travels over the app's `sendOTP` channel. */
const OTP_VERIFY_PATH = '/two-factor/verify-otp'

/** Better Auth's own error codes for a wrong second-factor code. */
const FAILED_GUESS_CODES: readonly string[] = ['INVALID_CODE', 'INVALID_BACKUP_CODE']

/**
 * First factors after which an emailed (or otherwise inbox-delivered)
 * two-factor OTP is independent proof: none of them is satisfied by
 * control of the inbox alone. `magic-link`, `email-otp` and `oauth`
 * sign-ins are (the IdP account usually IS the mailbox), and `null`
 * (no recorded method) proves nothing.
 */
const OTP_INDEPENDENT_FIRST_FACTORS: readonly AuthMethod[] = [
  'password',
  'passkey',
  'two-factor',
  'server-step-up',
]

/** Better Auth's `twoFactor({ accountLockout })`, resolved with BA's own defaults. */
export type LockoutConfig = {
  readonly enabled: boolean
  readonly maxFailedAttempts: number
  readonly durationMs: number
}

/**
 * What the before-hook established about one second-factor request.
 *
 * - `sign-in`: no session was presented; Better Auth's challenge path
 *   runs (and does its own counting and locking).
 * - `step-up`: a verification on the existing session `token`.
 *   `provesMfa` is true only when the factor was ALREADY enrolled
 *   before this request (a verification that enrols the first factor
 *   proves nothing for the session that enrolled it) and, for the OTP
 *   route, when the OTP channel is independent of the session's first
 *   factor. `twoFactorId` is the counter row, or `null` when the user
 *   has none (OTP-only enrolment — Better Auth keeps no counter for
 *   those on either path).
 */
export type StepUpAssessment =
  | { readonly kind: 'sign-in' }
  | {
      readonly kind: 'step-up'
      readonly token: string
      readonly userId: string
      readonly twoFactorId: string | null
      readonly provesMfa: boolean
      readonly lockout: LockoutConfig
    }

/** Wiring for the step-up guard. */
export type StepUpOptions = {
  /** See `BetterAuthEngineInput.twoFactorOtpChannelIndependent`. */
  readonly otpChannelIndependent: boolean
  readonly logger: LoggerPort
}

/** The Better Auth 1.7 hook-context fields this module reads. */
export type StepUpHookContext = {
  readonly path?: string | undefined
  readonly context: {
    session?: unknown
    readonly getPlugin?: ((id: string) => unknown) | undefined
    readonly internalAdapter?: {
      readonly findSession?: ((token: string) => Promise<unknown>) | undefined
      readonly findUserById?: ((id: string) => Promise<unknown>) | undefined
    }
    readonly adapter?: {
      readonly findOne?: ((query: Record<string, unknown>) => Promise<unknown>) | undefined
      readonly incrementOne?: ((query: Record<string, unknown>) => Promise<unknown>) | undefined
      readonly update?: ((query: Record<string, unknown>) => Promise<unknown>) | undefined
    }
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

function positiveNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback
}

/** BA's `resolveAccountLockoutConfig`, read from the installed `two-factor` plugin. */
export function lockoutConfigOf(ctx: StepUpHookContext): LockoutConfig {
  const plugin = record(ctx.context.getPlugin?.('two-factor'))
  const lockout = record(record(plugin?.options)?.accountLockout)
  return {
    enabled: lockout?.enabled !== false,
    maxFailedAttempts: positiveNumber(lockout?.maxFailedAttempts, 10),
    durationMs: positiveNumber(lockout?.durationSeconds, 900) * 1000,
  }
}

function dateOf(value: unknown): Date | null {
  if (value instanceof Date) {
    return value
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime()) ? null : parsed
  }
  return null
}

/** The `{ session, user }` pair Better Auth resolved, narrowed. */
function sessionPair(value: unknown): { token: string; userId: string } | null {
  const pair = record(value)
  const token = nonEmptyString(record(pair?.session)?.token)
  const userId = nonEmptyString(record(pair?.user)?.id)
  return token === null || userId === null ? null : { token, userId }
}

/**
 * Assess one second-factor request BEFORE its endpoint runs. The
 * presented session is resolved through Better Auth's own
 * `getSessionFromCtx` (passed in as `resolveSession`, run with refresh
 * disabled and its cache restored afterwards so the endpoint resolves —
 * and refreshes — exactly as it would without this hook). For a
 * step-up, the state that decides it is read FRESH from storage, never
 * from the cookie cache: the session's recorded first factor, the
 * user's enrolment flag, and the `twoFactor` row.
 *
 * Throws Better Auth's own `ACCOUNT_TEMPORARILY_LOCKED` (429) while the
 * account is locked — the step-up is refused before any code is
 * checked, exactly like the sign-in path. An expired lock is cleared
 * the way Better Auth clears it (guarded, so a concurrent fresh lock
 * survives).
 */
export async function assessSecondFactorRequest(
  ctx: StepUpHookContext,
  resolveSession: () => Promise<unknown>,
  options: StepUpOptions
): Promise<StepUpAssessment> {
  const cached = ctx.context.session
  let resolved: unknown
  try {
    resolved = await resolveSession()
  } finally {
    ctx.context.session = cached
  }
  const presented = sessionPair(resolved)
  if (presented === null) {
    return { kind: 'sign-in' }
  }
  const lockout = lockoutConfigOf(ctx)
  const fresh = record(await ctx.context.internalAdapter?.findSession?.(presented.token))
  const user = record(
    fresh?.user ?? (await ctx.context.internalAdapter?.findUserById?.(presented.userId))
  )
  const row = record(
    await ctx.context.adapter?.findOne?.({
      model: TWO_FACTOR_MODEL,
      where: [{ field: 'userId', value: presented.userId }],
    })
  )
  const twoFactorId = nonEmptyString(row?.id)
  if (lockout.enabled && row !== null && twoFactorId !== null) {
    const lockedUntil = dateOf(row.lockedUntil)
    if (lockedUntil !== null) {
      if (lockedUntil.getTime() > Date.now()) {
        options.logger.warn('better-auth two-factor step-up refused: account locked', {
          userId: presented.userId,
        })
        throw APIError.from('TOO_MANY_REQUESTS', {
          code: 'ACCOUNT_TEMPORARILY_LOCKED',
          message:
            'Too many failed verification attempts. Your account is temporarily locked. Please try again later.',
        })
      }
      await ctx.context.adapter?.incrementOne?.({
        model: TWO_FACTOR_MODEL,
        where: [
          { field: 'id', value: twoFactorId },
          { field: 'lockedUntil', operator: 'lte', value: new Date() },
        ],
        increment: {},
        set: { failedVerificationCount: 0, lockedUntil: null },
      })
    }
  }
  const isOtp = ctx.path === OTP_VERIFY_PATH
  // Enrolled BEFORE this request: the user has 2FA on, and (TOTP and
  // backup codes) the row is a confirmed one. The request that flips
  // either of these is an enrolment, not a proof.
  const enrolled =
    user?.twoFactorEnabled === true && (isOtp || (row !== null && row.verified !== false))
  const firstFactor = nonEmptyString(record(fresh?.session)?.authenticationMethod)
  const otpIndependent =
    options.otpChannelIndependent ||
    (firstFactor !== null &&
      (OTP_INDEPENDENT_FIRST_FACTORS as readonly string[]).includes(firstFactor))
  return {
    kind: 'step-up',
    token: presented.token,
    userId: presented.userId,
    twoFactorId,
    provesMfa: enrolled && (!isOtp || otpIndependent),
    lockout,
  }
}

/** How a second-factor endpoint ended, as far as the counter cares. */
export type SecondFactorOutcome = 'success' | 'failed-guess' | 'failed'

/**
 * Classify the endpoint's result: a 200 body is `success`; Better
 * Auth's own wrong-code errors are `failed-guess` (they spend the
 * budget); anything else (expired OTP, too many attempts on one code,
 * a server error) is `failed` and neither spends nor resets it.
 */
export function outcomeOf(returned: unknown): SecondFactorOutcome {
  if (returned === null || returned === undefined) {
    return 'failed'
  }
  if (isAPIError(returned)) {
    const code = record(returned.body)?.code
    return typeof code === 'string' && FAILED_GUESS_CODES.includes(code) ? 'failed-guess' : 'failed'
  }
  if (returned instanceof Response) {
    return returned.status === 200 ? 'success' : 'failed'
  }
  return 'success'
}

/**
 * Spend or reset the shared failure budget after a step-up, with
 * Better Auth's own write sequence: an atomic increment, then a guarded
 * lock once the budget is spent; a success clears both. A write that
 * fails is logged and swallowed — the request's own outcome stands.
 */
export async function accountStepUp(
  ctx: StepUpHookContext,
  assessment: Extract<StepUpAssessment, { kind: 'step-up' }>,
  outcome: SecondFactorOutcome,
  logger: LoggerPort
): Promise<void> {
  const { twoFactorId, lockout } = assessment
  if (twoFactorId === null || !lockout.enabled || outcome === 'failed') {
    return
  }
  const adapter = ctx.context.adapter
  const write =
    outcome === 'failed-guess'
      ? async (): Promise<void> => {
          const counted = record(
            await adapter?.incrementOne?.({
              model: TWO_FACTOR_MODEL,
              where: [{ field: 'id', value: twoFactorId }],
              increment: { failedVerificationCount: 1 },
            })
          )
          const count = counted?.failedVerificationCount
          if (typeof count === 'number' && count >= lockout.maxFailedAttempts) {
            await adapter?.incrementOne?.({
              model: TWO_FACTOR_MODEL,
              where: [
                { field: 'id', value: twoFactorId },
                {
                  field: 'failedVerificationCount',
                  operator: 'gte',
                  value: lockout.maxFailedAttempts,
                },
              ],
              increment: {},
              set: { lockedUntil: new Date(Date.now() + lockout.durationMs) },
            })
          }
        }
      : async (): Promise<void> => {
          await adapter?.update?.({
            model: TWO_FACTOR_MODEL,
            where: [{ field: 'id', value: twoFactorId }],
            update: { failedVerificationCount: 0, lockedUntil: null },
          })
        }
  const written = await ResultAsync.fromPromise(write(), (cause) => cause)
  if (written.isErr()) {
    logger.error('better-auth two-factor step-up: failure counter write failed', {
      userId: assessment.userId,
      outcome,
      cause: written.error instanceof Error ? written.error.message : 'unknown',
    })
  }
}
