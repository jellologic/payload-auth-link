import { APIError, createAuthMiddleware, getSessionFromCtx, isAPIError } from 'better-auth/api'
import type { BetterAuthPlugin } from 'better-auth'
import { nullLogger, type AuthMethod, type LoggerPort } from '@payload-auth-link/core'
import {
  assessFactorManagement,
  assessSecondFactorRequest,
  createSerializer,
  markFactorIssued,
  outcomeOf,
  settleSecondFactor,
  type FactorManagementAssessment,
  type StepUpAssessment,
} from './step-up.js'

/** The method value recorded on server-side mints (no 2FA challenge ran). */
export const MINT_METHOD: AuthMethod = 'server-mint'
/** The method recorded when the server vouches a second factor it verified itself. */
export const STEP_UP_METHOD: AuthMethod = 'server-step-up'
/** Session methods whose recorded value counts as an MFA proof. */
export const MFA_METHODS: readonly AuthMethod[] = [STEP_UP_METHOD, 'two-factor']

/**
 * The endpoints whose SUCCESS creates (or finally proves) a session,
 * mapped to the authentication method recorded on the session row.
 * Exact paths or prefixes — Better Auth's own route names, so the
 * mapping tracks the flow the app actually runs. Paths outside this
 * table record nothing (null), which fails closed at the MFA gate.
 */
const METHOD_BY_PATH: readonly {
  readonly matches: (path: string) => boolean
  readonly method: AuthMethod
}[] = [
  { matches: (path) => path.startsWith('/two-factor/verify'), method: 'two-factor' },
  { matches: (path) => path === '/sign-in/email', method: 'password' },
  { matches: (path) => path === '/magic-link/verify', method: 'magic-link' },
  // Better Auth 1.7's emailOTP sign-in route.
  { matches: (path) => path === '/sign-in/email-otp', method: 'email-otp' },
  {
    matches: (path) => path.startsWith('/callback/') || path.startsWith('/oauth2/callback/'),
    method: 'oauth',
  },
  { matches: (path) => path === '/passkey/authenticate', method: 'passkey' },
]

function methodForPath(path: string | undefined): AuthMethod | null {
  if (path === undefined) {
    return null
  }
  for (const entry of METHOD_BY_PATH) {
    if (entry.matches(path)) {
      return entry.method
    }
  }
  return null
}

/** `token.<base64 signature>` → `token`: strip BA's cookie signature. */
function stripSignature(value: string): string {
  const dot = value.lastIndexOf('.')
  return dot > 0 ? value.slice(0, dot) : value
}

/**
 * What the response's own Set-Cookie says about the session cookie:
 * `undefined` when it does not write the session cookie at all, `null`
 * when it EXPIRES it (an empty value: the session is gone, e.g. a
 * 2FA-pending sign-in), otherwise the raw token BA just issued.
 */
function tokenFromSetCookies(entries: readonly string[], name: string): string | null | undefined {
  let found: string | null | undefined
  for (const entry of entries) {
    if (!entry.startsWith(`${name}=`)) {
      continue
    }
    const pair = entry.slice(name.length + 1).split(';', 1)[0]
    // The LAST write wins in the browser, so it wins here too.
    found = pair === undefined || pair === '' ? null : stripSignature(pair)
  }
  return found
}

/** Whether the path proves a second factor ON the presented session. */
function isSecondFactorPath(path: string | undefined): boolean {
  return path !== undefined && path.startsWith('/two-factor/verify')
}

/**
 * Better Auth routes that issue, reveal, rotate or remove the user's
 * second factor (GHSA-xgx5-2cj5-x548). `/two-factor/view-backup-codes`
 * is server-only in Better Auth 1.7 and never reaches HTTP.
 */
const FACTOR_MANAGEMENT_PATHS: readonly string[] = [
  '/two-factor/enable',
  '/two-factor/get-totp-uri',
  '/two-factor/generate-backup-codes',
  '/two-factor/disable',
]

/** Management routes whose success hands out (or turns on) second-factor material. */
const FACTOR_ISSUING_PATHS: readonly string[] = [
  '/two-factor/enable',
  '/two-factor/get-totp-uri',
  '/two-factor/generate-backup-codes',
]

function isFactorManagementPath(path: string | undefined): boolean {
  return path !== undefined && FACTOR_MANAGEMENT_PATHS.includes(path)
}

function isFactorIssuingPath(path: string | undefined): boolean {
  return path !== undefined && FACTOR_ISSUING_PATHS.includes(path)
}

/** Whether the endpoint's returned value is a success (a 200 body). */
function succeeded(returned: unknown): boolean {
  if (returned === null || returned === undefined || isAPIError(returned)) {
    return false
  }
  return !(returned instanceof Response && returned.status !== 200)
}

/** The Better Auth 1.7 after-hook context fields this plugin reads. */
type ProvenanceHookContext = {
  readonly path?: string | undefined
  readonly getSignedCookie?:
    ((key: string, secret: string) => Promise<string | null | false>) | undefined
  readonly context: {
    readonly returned?: unknown
    readonly secret?: unknown
    readonly session?: unknown
    readonly authCookies?: { readonly sessionToken?: { readonly name?: unknown } }
    readonly responseHeaders?: Headers | undefined
    readonly internalAdapter?: {
      readonly updateSession?:
        ((token: string, data: Record<string, unknown>) => Promise<unknown>) | undefined
    }
  }
}

/** The token of the session BA resolved for this request (`ctx.context.session`). */
function resolvedSessionToken(session: unknown): string | null {
  if (typeof session !== 'object' || session === null || !('session' in session)) {
    return null
  }
  const row: unknown = session.session
  if (typeof row !== 'object' || row === null || !('token' in row)) {
    return null
  }
  const token: unknown = row.token
  return typeof token === 'string' && token !== '' ? token : null
}

/**
 * The presented session a second-factor verification authenticated
 * (step-up on an existing session), or `null`. Both sides must agree:
 * the request's session cookie, signature-verified through Better
 * Call's own `ctx.getSignedCookie` (the parser BA's `getSession` uses),
 * AND the session BA itself resolved for the request
 * (`ctx.context.session`, set by `getSessionFromCtx` inside the
 * verification). A request carrying a different or second session
 * cookie, a forged signature, or a session resolved from elsewhere
 * relabels nothing (fail closed).
 */
async function verifiedPresentedToken(
  ctx: ProvenanceHookContext,
  name: string
): Promise<string | null> {
  const secret = ctx.context.secret
  if (typeof ctx.getSignedCookie !== 'function' || typeof secret !== 'string' || secret === '') {
    return null
  }
  const resolved = resolvedSessionToken(ctx.context.session)
  if (resolved === null) {
    return null
  }
  const presented = await ctx.getSignedCookie(name, secret)
  if (typeof presented !== 'string' || presented === '' || presented !== resolved) {
    return null
  }
  return resolved
}

/**
 * The key the before-hook's assessment rides on, from the before-hook
 * to the after-hook of the SAME request: Better Auth merges a
 * before-hook's returned `context` into the endpoint context, which the
 * after-hooks receive.
 */
const ASSESSMENT_KEY = 'payloadAuthLinkSecondFactor'

/**
 * Assessments this module issued. The after-hook honours only these
 * (by identity), so a value planted on the context by anything else
 * relabels nothing (fail closed).
 */
const issuedAssessments = new WeakSet<StepUpAssessment>()

/** The key a factor-management assessment rides on (see {@link ASSESSMENT_KEY}). */
const MANAGEMENT_KEY = 'payloadAuthLinkFactorManagement'

/** Factor-management assessments this module issued (honoured by identity). */
const issuedManagement = new WeakSet<FactorManagementAssessment>()

function contextValue(ctx: unknown, key: string): object | null {
  if (typeof ctx !== 'object' || ctx === null || !(key in ctx)) {
    return null
  }
  const value: unknown = (ctx as Record<string, unknown>)[key]
  return typeof value === 'object' && value !== null ? value : null
}

function assessmentOf(ctx: unknown): StepUpAssessment | null {
  const value = contextValue(ctx, ASSESSMENT_KEY)
  return value !== null && issuedAssessments.has(value as StepUpAssessment)
    ? (value as StepUpAssessment)
    : null
}

function managementOf(ctx: unknown): FactorManagementAssessment | null {
  const value = contextValue(ctx, MANAGEMENT_KEY)
  return value !== null && issuedManagement.has(value as FactorManagementAssessment)
    ? (value as FactorManagementAssessment)
    : null
}

/**
 * The refusal for a factor-management request on a session without
 * MFA proof, when the user already holds an MFA-grade factor.
 */
function mfaSessionRequired(): APIError {
  return APIError.from('FORBIDDEN', {
    code: 'TWO_FACTOR_SESSION_REQUIRED',
    message:
      'Managing an enrolled second factor requires a session that completed two-factor verification. Sign in again with your second factor.',
  })
}

/** Options for {@link createSessionProvenancePlugin}. */
export type SessionProvenanceOptions = {
  /**
   * Whether the twoFactor OTP channel (`otpOptions.sendOTP`) is
   * independent of the user's email inbox. See
   * `BetterAuthEngineInput.twoFactorOtpChannelIndependent`.
   */
  readonly twoFactorOtpChannelIndependent?: boolean | undefined
  /** Logs lockout refusals and counter-write failures. */
  readonly logger?: LoggerPort | undefined
}

/**
 * The engine's internal session-provenance plugin. Four jobs:
 *
 * 1. **Schema** — one nullable, input-excluded field on Better Auth's
 *    session model: `authenticationMethod`, recording HOW the session
 *    came into being.
 * 2. **Recording** — `hooks.after` on the endpoints whose success
 *    creates (or finally proves) a session: password sign-in records
 *    `password`, the two-factor sign-in verification records
 *    `two-factor` on the session it issues (`password` when the second
 *    factor was an OTP over a channel not declared independent of the
 *    inbox), OAuth callbacks record `oauth`, and so on. The second
 *    factor's own endpoint is the only path that writes `two-factor`,
 *    and server-side mints write `server-mint`/`server-step-up`
 *    (port.ts).
 * 3. **Step-up guard (#110, GHSA-38wx-69j6-cgm7, GHSA-xgx5-2cj5-x548)**
 *    — a `hooks.before` on `/two-factor/verify*` assesses the request
 *    (step-up.ts): the attempt is reserved against the user's failure
 *    budget before any code is checked (refused while locked or once
 *    the budget is spent, shared with the sign-in path; OTP-only users
 *    get a budget too), and a correct code on an EXISTING session
 *    relabels it `two-factor` only when
 *    - the factor was enrolled BEFORE this request (the verification
 *      that enrols a factor proves nothing for the session that
 *      enrolled it; the session keeps its first-factor label),
 *    - no second-factor material was issued or revealed after the
 *      session was created (enrolment, `/two-factor/get-totp-uri`,
 *      `/two-factor/generate-backup-codes` — so a second verification
 *      on the enrolment session is no proof either),
 *    - for `/two-factor/verify-otp`, the OTP channel is declared
 *      independent of the inbox,
 *    - and the signature-verified request cookie names the session BA
 *      resolved for the request (`ctx.context.session`), which is the
 *      session assessed. A failed verification relabels nothing.
 * 4. **Factor-management gate (GHSA-xgx5-2cj5-x548)** — a
 *    `hooks.before` on `/two-factor/enable`, `get-totp-uri`,
 *    `generate-backup-codes` and `disable`: for a user who already
 *    holds an MFA-grade factor, the calling session must itself carry
 *    MFA provenance (`two-factor` / `server-step-up`), else the request
 *    is refused with 403 `TWO_FACTOR_SESSION_REQUIRED` — a password
 *    alone must not read the TOTP secret, mint backup codes, or swap
 *    or remove the factor. Every issuing call marks the factor issued,
 *    so no existing session can be stepped up with what it revealed.
 *
 * The server session API reads this per-session fact for its
 * assurance projection; enrollment flags are never consulted. Paths
 * outside the table and rows that predate the field record nothing —
 * `null` reads as "no recorded method", which the assurance projection
 * treats as proving nothing (fail closed).
 */
export function createSessionProvenancePlugin(
  options: SessionProvenanceOptions = {}
): BetterAuthPlugin {
  const logger = options.logger ?? nullLogger()
  const stepUpOptions = {
    otpChannelIndependent: options.twoFactorOtpChannelIndependent === true,
    logger,
    serialize: createSerializer(),
  }
  return {
    id: 'payload-auth-link-session-provenance',
    init: () => ({ context: {} }),
    schema: {
      session: {
        fields: {
          authenticationMethod: { type: 'string', required: false, input: false },
        },
      },
    },
    hooks:
      process.env.PROVENANCE_HOOKS_OFF === '1'
        ? undefined
        : {
            before: [
              {
                matcher: (ctx) => isSecondFactorPath(ctx.path),
                handler: createAuthMiddleware(async (ctx) => {
                  const assessment = await assessSecondFactorRequest(
                    ctx,
                    () => getSessionFromCtx(ctx, { disableRefresh: true }),
                    stepUpOptions
                  )
                  issuedAssessments.add(assessment)
                  return { context: { [ASSESSMENT_KEY]: assessment } }
                }),
              },
              {
                matcher: (ctx) => isFactorManagementPath(ctx.path),
                handler: createAuthMiddleware(async (ctx) => {
                  const assessment = await assessFactorManagement(
                    ctx,
                    () => getSessionFromCtx(ctx, { disableRefresh: true }),
                    stepUpOptions
                  )
                  if (assessment === null) {
                    // No session: Better Auth's session middleware refuses.
                    return
                  }
                  if (
                    assessment.holdsMfaFactor &&
                    !(MFA_METHODS as readonly (string | null)[]).includes(assessment.method)
                  ) {
                    logger.warn('better-auth two-factor management refused: no MFA session', {
                      userId: assessment.userId,
                      path: ctx.path,
                    })
                    throw mfaSessionRequired()
                  }
                  if (isFactorIssuingPath(ctx.path)) {
                    await markFactorIssued(ctx, assessment.userId)
                  }
                  issuedManagement.add(assessment)
                  return { context: { [MANAGEMENT_KEY]: assessment } }
                }),
              },
            ],
            after: [
              {
                matcher: (ctx) => methodForPath(ctx.path) !== null,
                handler: createAuthMiddleware(async (ctx) => {
                  const pathMethod = methodForPath(ctx.path)
                  if (pathMethod === null) {
                    return
                  }
                  const returned = (ctx.context as { returned?: unknown }).returned
                  const secondFactor = isSecondFactorPath(ctx.path)
                  const assessment = secondFactor ? assessmentOf(ctx) : null
                  if (assessment !== null) {
                    // Settle the reserved attempt: reset on success, keep
                    // a wrong guess, release anything else.
                    await settleSecondFactor(ctx, assessment, outcomeOf(returned), stepUpOptions)
                  }
                  // Record ONLY successful requests. BA's after-hooks run
                  // even when the endpoint returned an error response, so
                  // success must be checked explicitly. This mirrors BA's
                  // own `getEndpointResponse` (utils/plugin-helper): the
                  // endpoint's result must be a 200 body — non-2xx
                  // responses and thrown APIErrors record nothing (a
                  // wrong 2FA code must never relabel the presented
                  // session).
                  if (!succeeded(returned)) {
                    return
                  }
                  if (assessment?.kind === 'step-up' && assessment.enrolment) {
                    // The enrolment may have rotated the session: re-mark
                    // AFTER the rotation, so the rotated session (whose
                    // token only this response carries) predates it.
                    await markFactorIssued(ctx, assessment.userId)
                  }
                  const hook = ctx as unknown as ProvenanceHookContext
                  const name = hook.context.authCookies?.sessionToken?.name
                  const updateSession = hook.context.internalAdapter?.updateSession
                  if (
                    typeof name !== 'string' ||
                    name === '' ||
                    typeof updateSession !== 'function'
                  ) {
                    // Cannot resolve the token surface: record nothing rather
                    // than guess (fail closed).
                    return
                  }
                  // The response's own session cookie wins on sign-ins.
                  // An EXPIRING write means the session is gone: record
                  // nothing.
                  const issued = tokenFromSetCookies(
                    hook.context.responseHeaders?.getSetCookie?.() ?? [],
                    name
                  )
                  let method = pathMethod
                  let token: string | null
                  if (!secondFactor) {
                    // Other methods only ever create a session; with no
                    // issued cookie there is nothing to record.
                    token = issued ?? null
                  } else if (assessment === null) {
                    // No assessment from this module's before-hook:
                    // record nothing (fail closed).
                    token = null
                  } else if (assessment.kind === 'sign-in') {
                    // The challenge path issues a fresh session. If BA
                    // nevertheless authenticated a presented session,
                    // this was not the sign-in that was assessed. An OTP
                    // over a channel not declared independent of the
                    // inbox is not a second factor: the session keeps
                    // the password label of the sign-in it completes.
                    method = assessment.provesMfa ? pathMethod : 'password'
                    token =
                      resolvedSessionToken(hook.context.session) === null ? (issued ?? null) : null
                  } else if (!assessment.provesMfa || issued === null) {
                    // An enrolment, a factor newer than the session, an
                    // inbox-bound OTP, or a session that just went away.
                    token = null
                  } else {
                    // A step-up of exactly the session it authenticated
                    // (and that the before-hook assessed); a refresh may
                    // re-set the SAME token, never another one.
                    const presented = await verifiedPresentedToken(hook, name)
                    token =
                      presented === assessment.token &&
                      (issued === undefined || issued === presented)
                        ? presented
                        : null
                  }
                  if (token === null) {
                    return
                  }
                  await updateSession(token, { authenticationMethod: method })
                }),
              },
              {
                matcher: (ctx) => isFactorIssuingPath(ctx.path),
                handler: createAuthMiddleware(async (ctx) => {
                  const assessment = managementOf(ctx)
                  const returned = (ctx.context as { returned?: unknown }).returned
                  if (assessment === null || !succeeded(returned)) {
                    return
                  }
                  // `/two-factor/enable` may rotate the session (OTP
                  // method, skipVerificationOnEnable): re-mark after it.
                  await markFactorIssued(ctx, assessment.userId)
                }),
              },
            ],
          },
  }
}

/** The plugin with its defaults (no independent OTP channel, silent logger). */
export const sessionProvenancePlugin: BetterAuthPlugin = createSessionProvenancePlugin()
