import { isRecord, type LoggerPort } from '@payload-auth-link/core'
import type { BetterAuthPlugin } from 'better-auth'
import { createAuthMiddleware } from 'better-auth/api'

/**
 * Session-token redaction (issue #113, issue #116, security-model row 28).
 *
 * Better Auth's own HTTP endpoints hand the RAW session token to page
 * JavaScript: `/get-session` (`session.token`), `/list-sessions` (the
 * token of EVERY live session of the user), `/admin/list-user-sessions`,
 * the session-minting endpoints' bodies (`/sign-in/email` → `{ token }`,
 * …) and the second-factor verifications (`/two-factor/verify-*` →
 * `{ token, user }`, the presented session's token on a step-up). The
 * session cookie itself is `HttpOnly` precisely so script cannot read
 * it; a JSON copy of the same credential undoes that. With BA's
 * `bearer()` plugin installed (without `requireSignature`), the raw
 * token is a working `Authorization: Bearer` credential — one XSS away
 * from a stolen session on every device.
 *
 * The engine installs this plugin by default (`exposeSessionTokens`
 * opts out). For HTTP requests only — server-side `auth.api.*` calls
 * run in trusted code and keep the full shape (the port's own
 * `getSession` reads `session.token`) — its after-hook is default-deny:
 * it removes `token` from
 *
 * - every session-shaped object anywhere in the JSON body (a record
 *   carrying a string `token` next to a session field — `userId`,
 *   `expiresAt`, `ipAddress`, `userAgent` — or found under a `session`
 *   key),
 * - every `/list-sessions` entry (each keeps its `id`),
 * - a top-level body that pairs a string `token` with a `user` record
 *   (the session-minting and second-factor bodies),
 * - and any top-level `token` EQUAL to the session token the response
 *   just minted (`ctx.context.newSession`).
 *
 * A value that merely shares the key name (the `jwt` plugin's `/token`,
 * a one-time token, …) is never touched. Token hand-off protocols are
 * left alone by design: `/multi-session/*` (switching and revoking
 * device sessions takes the token) and `/one-time-token/*` (the
 * exchange returns the session).
 *
 * `/revoke-session` takes a session token; with the tokens redacted
 * from `/list-sessions`, its before-hook also accepts the listed
 * session `id` (the same opaque handle the server API uses, issue
 * #80) and resolves it to the token server-side. BA's endpoint still
 * enforces that the session belongs to the caller.
 */
export const sessionTokenRedactionPluginId = 'payload-auth-link-session-token-redaction'

/** Paths whose JSON hands a session token over on purpose. */
const handoffPrefixes: readonly string[] = ['/multi-session/', '/one-time-token/']

/** Fields that mark a record as a Better Auth session row. */
const sessionFields: readonly string[] = ['userId', 'expiresAt', 'ipAddress', 'userAgent']

/** How deep the walk descends (BA bodies nest a few levels at most). */
const maxDepth = 8

function withoutToken(row: Record<string, unknown>): Record<string, unknown> {
  const rest = { ...row }
  delete rest.token
  return rest
}

function tokenOf(session: unknown): string | null {
  if (!isRecord(session) || !isRecord(session.session)) {
    return null
  }
  const token = session.session.token
  return typeof token === 'string' && token !== '' ? token : null
}

/** A record that looks like a session row (or sits under a `session` key). */
function isSessionShaped(row: Record<string, unknown>, underSessionKey: boolean): boolean {
  return (
    typeof row.token === 'string' &&
    (underSessionKey || sessionFields.some((field) => field in row))
  )
}

/**
 * Strip `token` from every session-shaped object below `value`.
 * Returns the same reference when nothing changed.
 */
function redactDeep(value: unknown, underSessionKey: boolean, depth: number): unknown {
  if (depth > maxDepth) {
    return value
  }
  if (Array.isArray(value)) {
    let changed = false
    const entries = (value as unknown[]).map((entry) => {
      const next = redactDeep(entry, underSessionKey, depth + 1)
      changed ||= next !== entry
      return next
    })
    return changed ? entries : value
  }
  if (!isRecord(value) || value instanceof Date || value instanceof Response) {
    return value
  }
  let changed = false
  let body: Record<string, unknown> = value
  if (isSessionShaped(value, underSessionKey)) {
    body = withoutToken(value)
    changed = true
  }
  for (const [key, entry] of Object.entries(body)) {
    const next = redactDeep(entry, key === 'session' || key === 'sessions', depth + 1)
    if (next !== entry) {
      body = changed ? body : { ...body }
      body[key] = next
      changed = true
    }
  }
  return changed ? body : value
}

/**
 * The redacted body for one HTTP response, or `undefined` when nothing
 * needs to change. Pure — the hook below feeds it the endpoint path,
 * the endpoint's returned value, and the session the response minted.
 * Exported for the unit suite.
 */
export function redactSessionTokens(
  path: string | undefined,
  returned: unknown,
  newSession: unknown
): unknown {
  if (path === undefined || handoffPrefixes.some((prefix) => path.startsWith(prefix))) {
    return undefined
  }
  if (returned instanceof Response) {
    return undefined
  }
  // `/list-sessions` entries are session rows whatever fields they carry.
  let body = redactDeep(returned, path === '/list-sessions', 0)
  if (isRecord(body) && !Array.isArray(body) && typeof body.token === 'string') {
    const minted = tokenOf(newSession)
    if (isRecord(body.user) || (minted !== null && body.token === minted)) {
      body = withoutToken(body)
    }
  }
  return body === returned ? undefined : body
}

/** The hook-context fields this plugin reads (Better Auth 1.7). */
export type RedactionHookContext = {
  readonly path?: string | undefined
  readonly request?: unknown
  readonly body?: unknown
  readonly context: {
    readonly returned?: unknown
    readonly newSession?: unknown
    readonly adapter?: {
      readonly findOne?:
        | ((input: {
            model: string
            where: { field: string; value: string }[]
          }) => Promise<unknown>)
        | undefined
    }
  }
}

/** HTTP requests carry the `Request`; server `auth.api.*` calls do not. */
function isHttpRequest(ctx: { readonly request?: unknown }): boolean {
  return ctx.request instanceof Request
}

/**
 * `/revoke-session` body rewrite: a `token` that names a session ROW id
 * becomes that row's token. A real token never matches a row id, so
 * it passes through unchanged; an unknown value too (BA then answers
 * as it always does). Exported for the unit suite.
 */
export async function resolveRevokeHandle(
  ctx: RedactionHookContext
): Promise<{ context: { body: Record<string, unknown> } } | undefined> {
  const body = ctx.body
  if (!isRecord(body) || typeof body.token !== 'string' || body.token === '') {
    return undefined
  }
  const findOne = ctx.context.adapter?.findOne
  if (typeof findOne !== 'function') {
    return undefined
  }
  const row = await findOne({ model: 'session', where: [{ field: 'id', value: body.token }] })
  if (!isRecord(row) || typeof row.token !== 'string' || row.token === '') {
    return undefined
  }
  return { context: { body: { ...body, token: row.token } } }
}

/** The engine's session-token redaction plugin (see the module doc). */
export const sessionTokenRedactionPlugin: BetterAuthPlugin = {
  id: sessionTokenRedactionPluginId,
  hooks: {
    before: [
      {
        matcher: (ctx) => ctx.path === '/revoke-session',
        handler: createAuthMiddleware(async (ctx) =>
          resolveRevokeHandle(ctx as unknown as RedactionHookContext)
        ),
      },
    ],
    after: [
      {
        matcher: (ctx) => isHttpRequest(ctx),
        handler: createAuthMiddleware(async (ctx) => {
          const hook = ctx as unknown as RedactionHookContext
          const redacted = redactSessionTokens(
            hook.path,
            hook.context.returned,
            hook.context.newSession
          )
          if (redacted === undefined) {
            return
          }
          return ctx.json(redacted)
        }),
      },
    ],
  },
}

/** One plugin as the engine sees it in the builder's list. */
type InstalledPlugin = { readonly id: string; readonly options?: unknown }

/**
 * Wiring-time warning (issue #113): BA's `bearer()` plugin turns a raw
 * session token into a working `Authorization: Bearer` credential
 * unless `requireSignature` is set. Combined with a surface that hands
 * raw tokens to page JavaScript — `exposeSessionTokens: true`, or the
 * multi-session plugin's `/multi-session/list-device-sessions` — any
 * script on the page can lift a bearer credential. Warn loudly through
 * the logger; never `console.*`.
 */
export function reportSessionTokenExposure(
  plugins: readonly InstalledPlugin[],
  exposeSessionTokens: boolean,
  logger: LoggerPort
): void {
  const bearer = plugins.find((plugin) => plugin.id === 'bearer')
  if (bearer === undefined) {
    return
  }
  const options = bearer.options
  if (isRecord(options) && options.requireSignature === true) {
    // Raw (unsigned) tokens are refused as Bearer credentials.
    return
  }
  const surfaces: string[] = []
  if (exposeSessionTokens) {
    surfaces.push(
      'exposeSessionTokens: true (/get-session, /list-sessions and sign-in bodies return session.token)'
    )
  }
  if (plugins.some((plugin) => plugin.id === 'multi-session')) {
    surfaces.push(
      'the multi-session plugin (/multi-session/list-device-sessions returns every device session token)'
    )
  }
  for (const surface of surfaces) {
    logger.warn(
      `Better Auth bearer() is installed without requireSignature and ${surface}: page JavaScript can read raw session tokens that work as Authorization: Bearer credentials. Set bearer({ requireSignature: true }) or stop exposing the tokens.`,
      { setting: 'bearer', surface }
    )
  }
}
