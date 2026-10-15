import { readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative } from 'node:path'
import type { SourceFinding } from './types.js'

/**
 * Read-only source scan (issue #52): the call sites a payload-auth app
 * must migrate, found by pattern over `--src`. Regex-level on
 * purpose — the doctor must run before any code changes, on apps the
 * compiler cannot type-check against payload-auth-link yet.
 */

const scanExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mts', '.mjs'])
const skipDirs = new Set([
  'node_modules',
  'dist',
  '.next',
  '.turbo',
  'coverage',
  'test-results',
  'playwright-report',
])

const payloadAuthImport =
  /from\s+['"]payload-auth(?:\/[A-Za-z0-9_./-]+)?['"]|import\s*\(\s*['"]payload-auth(?:\/[A-Za-z0-9_./-]+)?['"]/g
const betterAuthAccessor = /\bpayload\.betterAuth\b|\bbetterAuth\.api\b/g
const getPayloadAuth = /\bgetPayloadAuth\s*\(/g
// Holding the Better Auth context at all (`$context`) means reaching
// past the supported surface — hand-hashed keys, hand-signed cookies —
// whether or not the call sits adjacent on one line.
const baInternals = /\$context\b|\binternalAdapter\b/g
// `req` and `request` are both idiomatic parameter names.
const reqUserField = /\b(?:req|request)\.user\.([A-Za-z_$][A-Za-z0-9_$]*)/g

/**
 * The fields the auth-link strategy projects onto `req.user` by
 * default (`reqUser: 'projection'`). Anything else a payload-auth app
 * reads off `req.user` is `undefined` under the projection — silent
 * access-control drift — until `reqUser: 'document'` lands (#57).
 */
export const projectedUserFields: ReadonlySet<string> = new Set([
  'id',
  'collection',
  'email',
  'roles',
  'mfaRequired',
  'assurance',
  'actor',
  'organizationId',
])

function walk(dir: string, into: string[]): void {
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return
  }
  for (const entry of entries) {
    if (skipDirs.has(entry) || entry.startsWith('.')) {
      continue
    }
    const full = join(dir, entry)
    let stats
    try {
      stats = statSync(full)
    } catch {
      continue
    }
    if (stats.isDirectory()) {
      walk(full, into)
    } else if (scanExtensions.has(extname(entry))) {
      into.push(full)
    }
  }
}

/**
 * Every scannable file under `dir` — the walk/skip rules the source
 * scan uses, shared with the plugin factory scan (issue #71).
 */
export function listSourceFiles(dir: string): readonly string[] {
  const files: string[] = []
  walk(dir, files)
  return files
}

export function scanSource(srcDir: string): SourceFinding[] {
  const files: string[] = []
  walk(srcDir, files)
  const importFiles = new Set<string>()
  const accessorFiles = new Set<string>()
  const getPayloadAuthFiles = new Set<string>()
  const internalsFiles = new Set<string>()
  const reqUserFiles = new Set<string>()
  const reqUserFields = new Set<string>()
  for (const file of files) {
    let content: string
    try {
      content = readFileSync(file, 'utf8')
    } catch {
      continue
    }
    const track = (pattern: RegExp, into: Set<string>): void => {
      pattern.lastIndex = 0
      if (pattern.test(content)) {
        into.add(file)
      }
    }
    track(payloadAuthImport, importFiles)
    track(betterAuthAccessor, accessorFiles)
    track(getPayloadAuth, getPayloadAuthFiles)
    track(baInternals, internalsFiles)
    for (const match of content.matchAll(reqUserField)) {
      const field = match[1]
      if (field !== undefined && !projectedUserFields.has(field)) {
        reqUserFields.add(field)
        reqUserFiles.add(file)
      }
    }
  }
  const rel = (file: string): string => relative(srcDir, file)
  const findings: SourceFinding[] = [
    {
      kind: 'payload-auth-import',
      files: [...importFiles].map(rel).sort(),
      fields: [],
      detail: 'imports from payload-auth; each becomes a payload-auth-link import (codemod, #53)',
    },
    {
      kind: 'get-payload-auth',
      files: [...getPayloadAuthFiles].map(rel).sort(),
      fields: [],
      detail: 'getPayloadAuth(config) call sites; become getPayload({ config }) (codemod, #53)',
    },
    {
      kind: 'better-auth-accessor',
      files: [...accessorFiles].map(rel).sort(),
      fields: [],
      detail:
        'payload.betterAuth accessors; migrate to the supported session API (#54), with the opt-in shim (#53) in between',
    },
    {
      kind: 'ba-internals',
      files: [...internalsFiles].map(rel).sort(),
      fields: [],
      detail:
        'Better Auth internals ($context.internalAdapter / $context.adapter) — unsupported; the supported server API replaces each bridge (#54)',
    },
    {
      kind: 'req-user-field',
      files: [...reqUserFiles].map(rel).sort(),
      fields: [...reqUserFields].sort(),
      detail:
        "req.user.<field> reads outside the session projection; under the default projection they read undefined — audit each or opt into reqUser: 'document' (#57)",
    },
  ]
  return findings.filter((finding) => finding.files.length > 0)
}
