/**
 * Codemods (issue #53): rule-based rewrites for the call sites a
 * payload-auth app must migrate. Deliberately textual and scoped —
 * each rule matches an exact, idiomatic payload-auth pattern and
 * leaves anything it cannot fully rewrite untouched (reported in the
 * result), because a half-rewritten call site is worse than an
 * explicit one.
 */

export type CodemodRule = {
  readonly id: string
  readonly description: string
  /** Apply to one file's content; returns the new content (same string when untouched). */
  readonly apply: (content: string) => string
}

export type CodemodFileResult = {
  readonly file: string
  readonly changed: boolean
  /** Rules that fired on this file. */
  readonly applied: readonly string[]
  /** Matches the rules could not fully rewrite (reported, never touched). */
  readonly manual: readonly string[]
}

export const codemodRules: readonly CodemodRule[] = [
  {
    id: 'get-payload-auth',
    description: 'getPayloadAuth() -> getPayload({ config })',
    apply: (content) =>
      content
        .replace(
          /import\s*\{\s*getPayloadAuth\s*(?:,[^}]*)?\}\s*from\s*['"]payload-auth['"];?/g,
          "import { getPayload } from 'payload'"
        )
        .replace(/\bgetPayloadAuth\(\s*\)/g, 'await getPayload({ config })'),
  },
  {
    id: 'better-auth-get-session',
    description:
      'payload.betterAuth.api.getSession({ headers }) -> authLinkServer(payload).getSession(headers)',
    apply: (content) =>
      content.replace(
        /payload\.betterAuth\.api\.getSession\(\s*\{\s*headers\s*\}\s*\)/g,
        '(await authLinkServer(payload)).getSession(headers)'
      ),
  },
  {
    id: 'to-next-js-handler',
    description:
      'toNextJsHandler(payload.betterAuth) -> createRouteHandlers from @payload-auth-link/next',
    apply: (content) =>
      content
        .replace(
          /import\s*\{\s*toNextJsHandler\s*\}\s*from\s*['"]better-auth\/next-js['"];?/g,
          "import { createRouteHandlers } from '@payload-auth-link/next'"
        )
        .replace(
          /export\s*\{\s*(\w+)\s+as\s+GET\s*,\s*(\w+)\s+as\s+POST\s*\}\s*=\s*toNextJsHandler\(\s*payload\.betterAuth\s*\)/g,
          'export const GET = createRouteHandlers.GET\nexport const POST = createRouteHandlers.POST'
        ),
  },
]

/**
 * Report call sites the rules cannot fully rewrite — each one needs a
 * human decision (which session API call, which route handler shape).
 */
export function findManualSites(content: string): readonly string[] {
  const manual: string[] = []
  if (/\bpayload\.betterAuth\.api\.(?!getSession\b)\w+/.test(content)) {
    manual.push('payload.betterAuth.api.<method> — see the authLinkServer session API (#54)')
  }
  if (/\$context\.(?:internalAdapter|adapter)\b/.test(content)) {
    manual.push('$context internals — see the supported server session API (#54)')
  }
  return manual
}

/** Apply every rule to one file; reports what fired and what needs a human. */
export function applyCodemods(file: string, content: string): CodemodFileResult {
  let current = content
  const applied: string[] = []
  for (const rule of codemodRules) {
    const next = rule.apply(current)
    if (next !== current) {
      applied.push(rule.id)
      current = next
    }
  }
  const manual = findManualSites(current)
  return { file, changed: current !== content, applied, manual }
}
