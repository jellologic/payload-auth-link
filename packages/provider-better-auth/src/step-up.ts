import { APIError, isAPIError } from 'better-auth/api'
import type { LoggerPort } from '@payload-auth-link/core'
import { ResultAsync } from 'neverthrow'

/**
 * Second-factor guard (GHSA-38wx-69j6-cgm7, GHSA-xgx5-2cj5-x548).
 * Better Auth's `twoFactor` plugin counts failed verifications and
 * locks the account only on the SIGN-IN challenge path, and only for
 * users with a `twoFactor` row; a verification presented on an
 * EXISTING session (a step-up) is neither counted nor refused while
 * the account is locked. Since the session-provenance plugin relabels
 * a stepped-up session `two-factor`, an uncounted step-up would make
 * the MFA gate brute-forceable. This module closes that gap:
 *
 * - **One budget.** Users with a `twoFactor` row spend Better Auth's
 *   OWN per-user counter (`failedVerificationCount` / `lockedUntil`,
 *   honouring the plugin's `accountLockout` options), so sign-in and
 *   step-up share one budget and one lock. Users without one (an
 *   OTP-only enrolment) spend a per-user window of attempt rows in
 *   Better Auth's `verification` model, on BOTH paths.
 * - **Reserve, then verify.** The attempt is reserved (the counter
 *   incremented, or an attempt row inserted) BEFORE the code is
 *   checked, so a concurrent burst cannot evaluate more codes than the
 *   budget allows; a success resets the budget, a non-guess failure
 *   releases its reservation.
 * - **Proof.** Whether a step-up may count as MFA proof at all (see
 *   {@link StepUpAssessment}): a factor issued or revealed after the
 *   session was created never proves anything for it.
 */

/** The Better Auth `twoFactor` model the counter lives on. */
const TWO_FACTOR_MODEL = 'twoFactor'

/** Better Auth's generic `verification` model (markers and attempt rows). */
const VERIFICATION_MODEL = 'verification'

/** The OTP verification route: its code travels over the app's `sendOTP` channel. */
const OTP_VERIFY_PATH = '/two-factor/verify-otp'

/** Better Auth's two-factor challenge cookie (`TWO_FACTOR_COOKIE_NAME`). */
const TWO_FACTOR_COOKIE = 'two_factor'

/** Better Auth's own error codes for a wrong second-factor code. */
const FAILED_GUESS_CODES: readonly string[] = ['INVALID_CODE', 'INVALID_BACKUP_CODE']

/** Identifier prefix of the "second-factor material last issued" marker. */
const ISSUED_PREFIX = 'payload-auth-link:two-factor-issued:'

/** Identifier prefix of a reserved second-factor attempt (users without a row). */
const ATTEMPT_PREFIX = 'payload-auth-link:two-factor-attempt:'

/**
 * How long an issuance marker is kept. It must outlive every session
 * created before it (a session refreshes indefinitely while in use),
 * so it is effectively permanent; a newer marker replaces it.
 */
const ISSUED_MARKER_LIFETIME_MS = 10 * 365 * 24 * 60 * 60 * 1000

/** Upper bound on marker rows read per user (concurrent writes may briefly leave two). */
const MARKER_SCAN_LIMIT = 100

/** Better Auth's `twoFactor({ accountLockout })`, resolved with BA's own defaults. */
export type LockoutConfig = {
  readonly enabled: boolean
  readonly maxFailedAttempts: number
  readonly durationMs: number
}

/**
 * A reserved slot in the user's failure budget.
 *
 * - `two-factor-row`: Better Auth's own counter on the user's
 *   `twoFactor` row; `reserved` is the count this attempt brought it to.
 * - `attempt-rows`: one `verification` row per counted attempt, for a
 *   user without a `twoFactor` row (OTP-only enrolment); `attemptId` is
 *   this attempt's row.
 */
export type FailureBudget =
  | { readonly kind: 'two-factor-row'; readonly twoFactorId: string; readonly reserved: number }
  | { readonly kind: 'attempt-rows'; readonly identifier: string; readonly attemptId: string }

/**
 * What the before-hook established about one second-factor request.
 *
 * - `sign-in`: no session was presented; Better Auth's challenge path
 *   runs (and counts users with a `twoFactor` row itself). `provesMfa`
 *   is false for `/two-factor/verify-otp` unless the OTP channel is
 *   declared independent of the inbox: an emailed OTP after a password
 *   the same inbox can reset is not a second factor.
 * - `step-up`: a verification on the existing session `token`.
 *   `provesMfa` is true only when the factor was enrolled before this
 *   request (`enrolment` is false), no second-factor material was
 *   issued or revealed after the session was created, and, for the OTP
 *   route, the OTP channel is declared independent.
 *
 * `budget` is the attempt this request reserved (`null`: none — lockout
 * disabled, or Better Auth counts this attempt itself).
 */
export type StepUpAssessment =
  | {
      readonly kind: 'sign-in'
      readonly userId: string | null
      readonly provesMfa: boolean
      readonly budget: FailureBudget | null
      readonly lockout: LockoutConfig
    }
  | {
      readonly kind: 'step-up'
      readonly token: string
      readonly userId: string
      readonly provesMfa: boolean
      readonly enrolment: boolean
      readonly budget: FailureBudget | null
      readonly lockout: LockoutConfig
    }

/**
 * What the before-hook established about a request that manages the
 * user's second factor (`/two-factor/enable`, `get-totp-uri`,
 * `generate-backup-codes`, `disable`).
 */
export type FactorManagementAssessment = {
  readonly userId: string
  /** The presented session's recorded method (`null`: none recorded). */
  readonly method: string | null
  /**
   * The user already holds a factor that proves MFA: two-factor is on
   * AND a confirmed TOTP row exists or the OTP channel is declared
   * independent. Only then can the factor be stolen by revealing or
   * rotating it, so only then is an MFA-proven session required.
   */
  readonly holdsMfaFactor: boolean
}

/** Runs `task` after every earlier task queued under the same key. */
export type Serializer = <T>(key: string, task: () => Promise<T>) => Promise<T>

/**
 * A per-key FIFO queue (in-process). Attempt reservations and budget
 * writes for one user run one at a time, so Better Auth's
 * compare-and-swap counter increment never contends with itself.
 */
export function createSerializer(): Serializer {
  const tails = new Map<string, Promise<void>>()
  return <T>(key: string, task: () => Promise<T>): Promise<T> => {
    const previous = tails.get(key) ?? Promise.resolve()
    const result = previous.then(task)
    const tail = result.then(
      () => undefined,
      () => undefined
    )
    tails.set(key, tail)
    void tail.then(() => {
      if (tails.get(key) === tail) {
        tails.delete(key)
      }
    })
    return result
  }
}

/** Wiring for the step-up guard. */
export type StepUpOptions = {
  /** See `BetterAuthEngineInput.twoFactorOtpChannelIndependent`. */
  readonly otpChannelIndependent: boolean
  readonly logger: LoggerPort
  /** Serializes reservations and budget writes per user. */
  readonly serialize: Serializer
}

/** One Better Auth adapter call, as the guard sees it (query in, row(s) out). */
export type AdapterOperation = (query: Record<string, unknown>) => Promise<unknown>

/** The Better Auth 1.7 hook-context fields this module reads. */
export type StepUpHookContext = {
  readonly path?: string | undefined
  readonly getSignedCookie?:
    ((key: string, secret: string) => Promise<string | null | false>) | undefined
  readonly context: {
    session?: unknown
    readonly secret?: unknown
    readonly getPlugin?: ((id: string) => unknown) | undefined
    readonly createAuthCookie?: ((name: string) => unknown) | undefined
    readonly internalAdapter?: {
      readonly findSession?: ((token: string) => Promise<unknown>) | undefined
      readonly findUserById?: ((id: string) => Promise<unknown>) | undefined
      readonly findVerificationValue?: ((identifier: string) => Promise<unknown>) | undefined
    }
    readonly adapter?: {
      readonly findOne?: AdapterOperation | undefined
      readonly findMany?: AdapterOperation | undefined
      readonly count?: AdapterOperation | undefined
      readonly create?: AdapterOperation | undefined
      readonly incrementOne?: AdapterOperation | undefined
      readonly update?: AdapterOperation | undefined
      readonly delete?: AdapterOperation | undefined
      readonly deleteMany?: AdapterOperation | undefined
    }
  }
}

type AdapterOperationName = keyof NonNullable<StepUpHookContext['context']['adapter']>

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

function positiveNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback
}

/**
 * The adapter operation `name`, or a thrown error: every write this
 * guard needs is part of Better Auth's adapter contract, and a guard
 * that silently skipped one would fail open.
 */
function operation(ctx: StepUpHookContext, name: AdapterOperationName): AdapterOperation {
  const found = ctx.context.adapter?.[name]
  if (typeof found !== 'function') {
    throw new Error(`better-auth two-factor guard: adapter.${name} is unavailable`)
  }
  return found
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
 * The presented session, resolved through Better Auth's own
 * `getSessionFromCtx` (passed in as `resolveSession`, run with refresh
 * disabled and its cache restored afterwards so the endpoint resolves —
 * and refreshes — exactly as it would without this hook).
 */
async function presentedSession(
  ctx: StepUpHookContext,
  resolveSession: () => Promise<unknown>
): Promise<{ token: string; userId: string } | null> {
  const cached = ctx.context.session
  let resolved: unknown
  try {
    resolved = await resolveSession()
  } finally {
    ctx.context.session = cached
  }
  return sessionPair(resolved)
}

async function twoFactorRowOf(
  ctx: StepUpHookContext,
  userId: string
): Promise<Record<string, unknown> | null> {
  return record(
    await ctx.context.adapter?.findOne?.({
      model: TWO_FACTOR_MODEL,
      where: [{ field: 'userId', value: userId }],
    })
  )
}

/** The FRESH session row, user, and `twoFactor` row (never the cookie cache). */
async function freshState(
  ctx: StepUpHookContext,
  presented: { token: string; userId: string }
): Promise<{
  session: Record<string, unknown> | null
  user: Record<string, unknown> | null
  row: Record<string, unknown> | null
}> {
  const fresh = record(await ctx.context.internalAdapter?.findSession?.(presented.token))
  const user = record(
    fresh?.user ?? (await ctx.context.internalAdapter?.findUserById?.(presented.userId))
  )
  return { session: record(fresh?.session), user, row: await twoFactorRowOf(ctx, presented.userId) }
}

function lockedError(): APIError {
  return APIError.from('TOO_MANY_REQUESTS', {
    code: 'ACCOUNT_TEMPORARILY_LOCKED',
    message:
      'Too many failed verification attempts. Your account is temporarily locked. Please try again later.',
  })
}

/**
 * When the user's second-factor material was last issued or revealed
 * (epoch ms), or `null` when no marker exists (an enrolment that
 * predates this guard). An unreadable marker counts as newer than any
 * session (fail closed).
 */
export async function factorIssuedAt(
  ctx: StepUpHookContext,
  userId: string
): Promise<number | null> {
  const rows = await operation(
    ctx,
    'findMany'
  )({
    model: VERIFICATION_MODEL,
    where: [{ field: 'identifier', value: `${ISSUED_PREFIX}${userId}` }],
    limit: MARKER_SCAN_LIMIT,
  })
  if (!Array.isArray(rows)) {
    throw new Error('better-auth two-factor guard: marker lookup returned no rows array')
  }
  let latest: number | null = null
  for (const row of rows as unknown[]) {
    const at = dateOf(record(row)?.value)
    const time = at === null ? Number.POSITIVE_INFINITY : at.getTime()
    latest = latest === null ? time : Math.max(latest, time)
  }
  return latest
}

/**
 * Record that the user's second-factor material was issued or revealed
 * now (GHSA-xgx5-2cj5-x548): no session created before this moment can
 * be relabelled `two-factor` by a step-up afterwards. The new marker is
 * written before the old ones are removed, so a concurrent reader
 * always sees one.
 */
export async function markFactorIssued(ctx: StepUpHookContext, userId: string): Promise<void> {
  const identifier = `${ISSUED_PREFIX}${userId}`
  const previous = await operation(
    ctx,
    'findMany'
  )({
    model: VERIFICATION_MODEL,
    where: [{ field: 'identifier', value: identifier }],
    limit: MARKER_SCAN_LIMIT,
  })
  const now = Date.now()
  await operation(
    ctx,
    'create'
  )({
    model: VERIFICATION_MODEL,
    data: {
      identifier,
      value: new Date(now).toISOString(),
      expiresAt: new Date(now + ISSUED_MARKER_LIFETIME_MS),
    },
  })
  const remove = operation(ctx, 'delete')
  for (const row of Array.isArray(previous) ? (previous as unknown[]) : []) {
    const id = nonEmptyString(record(row)?.id)
    if (id !== null) {
      await remove({ model: VERIFICATION_MODEL, where: [{ field: 'id', value: id }] })
    }
  }
}

/** Lock the row once its counter has reached the budget (guarded, as Better Auth does). */
async function lockRow(
  ctx: StepUpHookContext,
  twoFactorId: string,
  lockout: LockoutConfig
): Promise<void> {
  await operation(
    ctx,
    'incrementOne'
  )({
    model: TWO_FACTOR_MODEL,
    where: [
      { field: 'id', value: twoFactorId },
      { field: 'failedVerificationCount', operator: 'gte', value: lockout.maxFailedAttempts },
    ],
    increment: {},
    set: { lockedUntil: new Date(Date.now() + lockout.durationMs) },
  })
}

/**
 * Reserve one attempt on Better Auth's own counter. Refused (429)
 * while the row is locked or once the reservation would exceed the
 * budget; an expired lock is cleared first, guarded so a concurrent
 * fresh lock survives.
 */
async function reserveOnRow(
  ctx: StepUpHookContext,
  userId: string,
  twoFactorId: string,
  lockout: LockoutConfig,
  logger: LoggerPort
): Promise<FailureBudget | null> {
  const row = record(
    await operation(
      ctx,
      'findOne'
    )({
      model: TWO_FACTOR_MODEL,
      where: [{ field: 'id', value: twoFactorId }],
    })
  )
  if (row === null) {
    // Two-factor was turned off meanwhile; Better Auth answers the request.
    return null
  }
  const lockedUntil = dateOf(row.lockedUntil)
  if (lockedUntil !== null) {
    if (lockedUntil.getTime() > Date.now()) {
      logger.warn('better-auth two-factor step-up refused: account locked', { userId })
      throw lockedError()
    }
    await operation(
      ctx,
      'incrementOne'
    )({
      model: TWO_FACTOR_MODEL,
      where: [
        { field: 'id', value: twoFactorId },
        { field: 'lockedUntil', operator: 'lte', value: new Date() },
      ],
      increment: {},
      set: { failedVerificationCount: 0, lockedUntil: null },
    })
  }
  const counted = record(
    await operation(
      ctx,
      'incrementOne'
    )({
      model: TWO_FACTOR_MODEL,
      where: [{ field: 'id', value: twoFactorId }],
      increment: { failedVerificationCount: 1 },
    })
  )
  const reserved = counted?.failedVerificationCount
  if (typeof reserved !== 'number' || !Number.isFinite(reserved)) {
    throw new Error('better-auth two-factor guard: the attempt could not be reserved')
  }
  if (reserved > lockout.maxFailedAttempts) {
    await lockRow(ctx, twoFactorId, lockout)
    logger.warn('better-auth two-factor step-up refused: failure budget spent', { userId })
    throw lockedError()
  }
  return { kind: 'two-factor-row', twoFactorId, reserved }
}

/**
 * Reserve one attempt for a user without a `twoFactor` row: insert an
 * attempt row (expiring after the lockout duration), then count the
 * live ones. Insert-then-count is race-free across processes too —
 * every concurrent attempt sees every other — and an attempt beyond
 * the budget removes its own row and is refused (429). The budget is
 * therefore `maxFailedAttempts` failures per `durationSeconds` window.
 */
async function reserveAttemptRow(
  ctx: StepUpHookContext,
  userId: string,
  lockout: LockoutConfig,
  logger: LoggerPort
): Promise<FailureBudget> {
  const identifier = `${ATTEMPT_PREFIX}${userId}`
  const now = Date.now()
  const created = record(
    await operation(
      ctx,
      'create'
    )({
      model: VERIFICATION_MODEL,
      data: { identifier, value: 'reserved', expiresAt: new Date(now + lockout.durationMs) },
    })
  )
  const attemptId = nonEmptyString(created?.id)
  if (attemptId === null) {
    throw new Error('better-auth two-factor guard: the attempt could not be reserved')
  }
  const live = await operation(
    ctx,
    'count'
  )({
    model: VERIFICATION_MODEL,
    where: [
      { field: 'identifier', value: identifier },
      { field: 'expiresAt', operator: 'gt', value: new Date(now) },
    ],
  })
  if (typeof live !== 'number' || live > lockout.maxFailedAttempts) {
    await operation(
      ctx,
      'delete'
    )({
      model: VERIFICATION_MODEL,
      where: [{ field: 'id', value: attemptId }],
    })
    logger.warn('better-auth two-factor verification refused: failure budget spent', { userId })
    throw lockedError()
  }
  return { kind: 'attempt-rows', identifier, attemptId }
}

/** The user a sign-in challenge (the signed `two_factor` cookie) belongs to, or `null`. */
async function challengedUserId(ctx: StepUpHookContext): Promise<string | null> {
  const secret = ctx.context.secret
  const createAuthCookie = ctx.context.createAuthCookie
  const findVerificationValue = ctx.context.internalAdapter?.findVerificationValue
  if (
    typeof ctx.getSignedCookie !== 'function' ||
    typeof secret !== 'string' ||
    secret === '' ||
    typeof createAuthCookie !== 'function' ||
    typeof findVerificationValue !== 'function'
  ) {
    return null
  }
  const name = nonEmptyString(record(createAuthCookie(TWO_FACTOR_COOKIE))?.name)
  if (name === null) {
    return null
  }
  const identifier = nonEmptyString(await ctx.getSignedCookie(name, secret))
  if (identifier === null) {
    return null
  }
  return nonEmptyString(record(await findVerificationValue(identifier))?.value)
}

/**
 * Assess one second-factor request BEFORE its endpoint runs, and
 * reserve its attempt. For a step-up, the state that decides it is
 * read FRESH from storage, never from the cookie cache: the session
 * row (its creation time), the user's enrolment flag, the `twoFactor`
 * row and the issuance marker.
 *
 * Throws Better Auth's own `ACCOUNT_TEMPORARILY_LOCKED` (429) while the
 * account is locked or once the budget is spent — the request is
 * refused before any code is checked, exactly like the sign-in path.
 * A verification that would ENROL a factor marks the factor issued
 * first, so no session that exists while it completes can later be
 * relabelled by it.
 */
export async function assessSecondFactorRequest(
  ctx: StepUpHookContext,
  resolveSession: () => Promise<unknown>,
  options: StepUpOptions
): Promise<StepUpAssessment> {
  const isOtp = ctx.path === OTP_VERIFY_PATH
  const otpProves = !isOtp || options.otpChannelIndependent
  const lockout = lockoutConfigOf(ctx)
  const presented = await presentedSession(ctx, resolveSession)
  if (presented === null) {
    // Better Auth counts users with a row itself on this path; the
    // others (OTP-only) spend the attempt-row budget here.
    const userId = await challengedUserId(ctx)
    const budget =
      userId !== null && lockout.enabled && (await twoFactorRowOf(ctx, userId)) === null
        ? await options.serialize(userId, () =>
            reserveAttemptRow(ctx, userId, lockout, options.logger)
          )
        : null
    return { kind: 'sign-in', userId, provesMfa: otpProves, budget, lockout }
  }
  const { session, user, row } = await freshState(ctx, presented)
  const twoFactorId = nonEmptyString(row?.id)
  // Enrolled BEFORE this request: the user has 2FA on, and (TOTP and
  // backup codes) the row is a confirmed one. The request that flips
  // either of these is an enrolment, not a proof.
  const enrolledBefore =
    user?.twoFactorEnabled === true && (isOtp || (row !== null && row.verified !== false))
  if (!enrolledBefore) {
    await markFactorIssued(ctx, presented.userId)
  }
  let budget: FailureBudget | null = null
  if (lockout.enabled) {
    budget = await options.serialize(presented.userId, () =>
      twoFactorId === null
        ? reserveAttemptRow(ctx, presented.userId, lockout, options.logger)
        : reserveOnRow(ctx, presented.userId, twoFactorId, lockout, options.logger)
    )
  }
  let provesMfa = false
  if (enrolledBefore && otpProves) {
    // The factor must predate the session: a factor issued or revealed
    // on (or after the creation of) this session proves nothing for it.
    const issuedAt = await factorIssuedAt(ctx, presented.userId)
    const createdAt = dateOf(session?.createdAt)
    provesMfa = issuedAt === null || (createdAt !== null && createdAt.getTime() > issuedAt)
  }
  return {
    kind: 'step-up',
    token: presented.token,
    userId: presented.userId,
    provesMfa,
    enrolment: !enrolledBefore,
    budget,
    lockout,
  }
}

/**
 * Assess a request that manages the user's second factor, BEFORE its
 * endpoint runs. Returns `null` when no session is presented (Better
 * Auth's session middleware then refuses the request itself).
 */
export async function assessFactorManagement(
  ctx: StepUpHookContext,
  resolveSession: () => Promise<unknown>,
  options: Pick<StepUpOptions, 'otpChannelIndependent'>
): Promise<FactorManagementAssessment | null> {
  const presented = await presentedSession(ctx, resolveSession)
  if (presented === null) {
    return null
  }
  const { session, user, row } = await freshState(ctx, presented)
  const confirmedTotp = row !== null && row.verified !== false
  return {
    userId: presented.userId,
    method: nonEmptyString(session?.authenticationMethod),
    holdsMfaFactor:
      user?.twoFactorEnabled === true && (confirmedTotp || options.otpChannelIndependent),
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

async function settleBudget(
  ctx: StepUpHookContext,
  budget: FailureBudget,
  lockout: LockoutConfig,
  outcome: SecondFactorOutcome
): Promise<void> {
  if (budget.kind === 'two-factor-row') {
    if (outcome === 'success') {
      await operation(
        ctx,
        'update'
      )({
        model: TWO_FACTOR_MODEL,
        where: [{ field: 'id', value: budget.twoFactorId }],
        update: { failedVerificationCount: 0, lockedUntil: null },
      })
    } else if (outcome === 'failed-guess') {
      if (budget.reserved >= lockout.maxFailedAttempts) {
        await lockRow(ctx, budget.twoFactorId, lockout)
      }
    } else {
      await operation(
        ctx,
        'incrementOne'
      )({
        model: TWO_FACTOR_MODEL,
        where: [
          { field: 'id', value: budget.twoFactorId },
          { field: 'failedVerificationCount', operator: 'gte', value: 1 },
        ],
        increment: { failedVerificationCount: -1 },
      })
    }
    return
  }
  if (outcome === 'success') {
    await operation(
      ctx,
      'deleteMany'
    )({
      model: VERIFICATION_MODEL,
      where: [{ field: 'identifier', value: budget.identifier }],
    })
  } else if (outcome === 'failed') {
    await operation(
      ctx,
      'delete'
    )({
      model: VERIFICATION_MODEL,
      where: [{ field: 'id', value: budget.attemptId }],
    })
  }
  // A wrong guess keeps its reservation: it IS the counted failure.
}

/**
 * Settle the attempt the before-hook reserved: a success resets the
 * budget (Better Auth counts consecutive failures only), a wrong guess
 * keeps its reservation and locks the row once the budget is spent,
 * and any other failure releases the reservation. A write that fails
 * is logged and swallowed — the request's own outcome stands.
 */
export async function settleSecondFactor(
  ctx: StepUpHookContext,
  assessment: StepUpAssessment,
  outcome: SecondFactorOutcome,
  options: Pick<StepUpOptions, 'logger' | 'serialize'>
): Promise<void> {
  const { budget, lockout, userId } = assessment
  if (budget === null || userId === null) {
    return
  }
  const written = await ResultAsync.fromPromise(
    options.serialize(userId, () => settleBudget(ctx, budget, lockout, outcome)),
    (cause) => cause
  )
  if (written.isErr()) {
    options.logger.error('better-auth two-factor step-up: failure counter write failed', {
      userId,
      outcome,
      cause: written.error instanceof Error ? written.error.message : 'unknown',
    })
  }
}
