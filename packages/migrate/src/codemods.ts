import * as ts from 'typescript'

/**
 * Codemods (issues #53, #70): rule-based rewrites for the call sites a
 * payload-auth app must migrate, matched on the TypeScript AST and
 * applied as text splices over the original ranges (no printer —
 * formatting survives).
 *
 * Each rule rewrites only what it can FULLY rewrite and reports the
 * rest as manual sites ({@link findManualSites}); a half-rewritten
 * call site is worse than an explicit one. In particular, a file with
 * ANY unrewritable `getPayloadAuth` reference keeps its whole
 * `get-payload-auth` state untouched, so the output never references a
 * symbol no import provides.
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
  /** The rewritten content — equal to the input when nothing changed. */
  readonly after: string
}

// --- shared parsing helpers -----------------------------------------------

function parse(content: string): ts.SourceFile {
  return ts.createSourceFile('codemod-input.ts', content, ts.ScriptTarget.Latest, true)
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1
}

type Splice = { readonly start: number; readonly end: number; readonly text: string }

function applySplices(content: string, splices: readonly Splice[]): string {
  let out = content
  for (const splice of [...splices].sort((a, b) => b.start - a.start)) {
    out = out.slice(0, splice.start) + splice.text + out.slice(splice.end)
  }
  return out
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Whether the node sits where `await` is legal: inside an async
 * function-like, or at module top level (top-level await). The cheap
 * heuristic walks to the nearest enclosing function-like and looks for
 * the `async` keyword (#70).
 */
function awaitContext(node: ts.Node): 'awaitable' | 'sync-function' {
  let current: ts.Node | undefined = node.parent
  while (current !== undefined) {
    if (
      ts.isFunctionDeclaration(current) ||
      ts.isMethodDeclaration(current) ||
      ts.isArrowFunction(current) ||
      ts.isFunctionExpression(current) ||
      ts.isGetAccessorDeclaration(current) ||
      ts.isSetAccessorDeclaration(current)
    ) {
      const async =
        current.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword) === true
      return async ? 'awaitable' : 'sync-function'
    }
    current = current.parent
  }
  return 'awaitable'
}

/** The module specifier of a static import declaration. */
function moduleSpecifierOf(statement: ts.ImportDeclaration): string {
  const specifier = statement.moduleSpecifier
  return ts.isStringLiteral(specifier) ? specifier.text : ''
}

function soleNamedElement(statement: ts.ImportDeclaration): boolean {
  const clause = statement.importClause
  return (
    clause !== undefined &&
    clause.name === undefined &&
    clause.namedBindings !== undefined &&
    ts.isNamedImports(clause.namedBindings) &&
    clause.namedBindings.elements.length === 1
  )
}

/**
 * Splice that removes one named import element plus an adjacent comma,
 * keeping the rest of the clause valid.
 */
function removeElementSplice(
  statement: ts.ImportDeclaration,
  element: ts.ImportSpecifier,
  source: ts.SourceFile
): Splice {
  const elements = statement.importClause?.namedBindings
  if (elements === undefined || !ts.isNamedImports(elements)) {
    return { start: element.getStart(source), end: element.getEnd(), text: '' }
  }
  const index = elements.elements.indexOf(element)
  const next = index >= 0 ? elements.elements[index + 1] : undefined
  if (next !== undefined) {
    return { start: element.getStart(source), end: next.getStart(source), text: '' }
  }
  const previous = index > 0 ? elements.elements[index - 1] : undefined
  if (previous !== undefined) {
    return { start: previous.getEnd(), end: element.getEnd(), text: '' }
  }
  return { start: element.getStart(source), end: element.getEnd(), text: '' }
}

// --- getPayloadAuth (#70.1) -------------------------------------------------

const payloadAuthModule = /^payload-auth(?:\/[A-Za-z0-9_./-]+)?$/

type PayloadAuthImport = {
  readonly statement: ts.ImportDeclaration
  readonly element: ts.ImportSpecifier
  /** The name the file binds (`getPayloadAuth`, or its alias). */
  readonly local: string
  readonly typeOnly: boolean
}

type PayloadAuthRef = {
  readonly node: ts.Identifier
  readonly kind: 'call' | 'type' | 'value'
  /** The enclosing call expression when `kind === 'call'`. */
  readonly call?: ts.CallExpression
  /** The full-rewrite replacement when `kind === 'call'` and rewritable. */
  readonly replacement?: string
  /** The manual-site message when this reference cannot be rewritten. */
  readonly reason?: string
}

function hasPayloadConfigImport(source: ts.SourceFile): boolean {
  let found = false
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      if (moduleSpecifierOf(node) === '@payload-config') {
        found = true
      }
    } else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length === 1
    ) {
      const arg = node.arguments[0]
      if (arg !== undefined && ts.isStringLiteral(arg) && arg.text === '@payload-config') {
        found = true
      }
    }
    if (!found) {
      ts.forEachChild(node, visit)
    }
  }
  visit(source)
  return found
}

/**
 * Every `getPayloadAuth` (or aliased) import and reference in the file,
 * classified: a call that can be fully rewritten carries its
 * replacement; anything else carries its manual-site reason.
 */
function analyzePayloadAuth(content: string): {
  readonly source: ts.SourceFile
  readonly imports: readonly PayloadAuthImport[]
  readonly refs: readonly PayloadAuthRef[]
} {
  const source = parse(content)
  const imports: PayloadAuthImport[] = []
  for (const statement of source.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !payloadAuthModule.test(moduleSpecifierOf(statement))
    ) {
      continue
    }
    const clause = statement.importClause
    if (
      clause === undefined ||
      clause.namedBindings === undefined ||
      !ts.isNamedImports(clause.namedBindings)
    ) {
      continue
    }
    for (const element of clause.namedBindings.elements) {
      const exported = element.propertyName ?? element.name
      if (!ts.isIdentifier(exported) || exported.text !== 'getPayloadAuth') {
        continue
      }
      imports.push({
        statement,
        element,
        local: element.name.text,
        typeOnly: clause.isTypeOnly || element.isTypeOnly,
      })
    }
  }
  const locals = new Set(imports.map((imp) => imp.local))
  const bindings = new Set<ts.Identifier>()
  for (const imp of imports) {
    bindings.add(imp.element.name)
    const exported = imp.element.propertyName
    if (exported !== undefined && ts.isIdentifier(exported)) {
      bindings.add(exported)
    }
  }
  const payloadConfig = hasPayloadConfigImport(source)
  const refs: PayloadAuthRef[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && locals.has(node.text) && !bindings.has(node)) {
      const parent = node.parent
      if (ts.isCallExpression(parent) && parent.expression === node) {
        const context = awaitContext(parent)
        const argCount = parent.arguments.length
        const firstArg = parent.arguments[0]
        if (context === 'sync-function') {
          refs.push({
            node,
            kind: 'call',
            call: parent,
            reason: `getPayloadAuth (line ${lineOf(source, parent)}) — the enclosing function is not async: make it async and use await getPayload({ config })`,
          })
        } else if (argCount === 0) {
          if (payloadConfig) {
            refs.push({
              node,
              kind: 'call',
              call: parent,
              replacement: '(await getPayload({ config }))',
            })
          } else {
            refs.push({
              node,
              kind: 'call',
              call: parent,
              reason: `getPayloadAuth() (line ${lineOf(source, parent)}) — the no-arg form needs this file to import from '@payload-config'; add that import and use await getPayload({ config })`,
            })
          }
        } else if (argCount === 1 && firstArg !== undefined) {
          refs.push({
            node,
            kind: 'call',
            call: parent,
            replacement: `(await getPayload({ config: ${firstArg.getText(source)} }))`,
          })
        } else {
          refs.push({
            node,
            kind: 'call',
            call: parent,
            reason: `getPayloadAuth (line ${lineOf(source, parent)}) — unexpected call shape (${argCount} arguments); call await getPayload({ config }) by hand`,
          })
        }
      } else if (ts.isTypeQueryNode(parent) && parent.exprName === node) {
        refs.push({
          node,
          kind: 'type',
          reason: `getPayloadAuth type reference (line ${lineOf(source, node)}) — use payload's own types instead: import type { Payload } from 'payload'`,
        })
      } else {
        refs.push({
          node,
          kind: 'value',
          reason: `getPayloadAuth value reference (line ${lineOf(source, node)}) — rewrite by hand to await getPayload({ config })`,
        })
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return { source, imports, refs }
}

/**
 * The get-payload-auth rewrite (issue #70): ALL references rewritable,
 * or nothing. A single manual site keeps the whole file's
 * getPayloadAuth state untouched — the output must never reference a
 * symbol no import provides.
 */
function rewritePayloadAuth(content: string): string {
  const { source, imports, refs } = analyzePayloadAuth(content)
  if (imports.length === 0 && refs.length === 0) {
    return content
  }
  if (refs.some((ref) => ref.reason !== undefined)) {
    return content
  }
  if (imports.some((imp) => imp.typeOnly)) {
    return content
  }
  const splices: Splice[] = []
  for (const ref of refs) {
    if (ref.kind === 'call' && ref.call !== undefined && ref.replacement !== undefined) {
      splices.push({
        start: ref.call.getStart(source),
        end: ref.call.getEnd(),
        text: ref.replacement,
      })
    }
  }
  for (const imp of imports) {
    if (soleNamedElement(imp.statement)) {
      splices.push({
        start: imp.statement.getStart(source),
        end: imp.statement.getEnd(),
        text: "import { getPayload } from 'payload'",
      })
    } else {
      splices.push(removeElementSplice(imp.statement, imp.element, source))
      splices.push({
        start: imp.statement.getStart(source),
        end: imp.statement.getStart(source),
        text: "import { getPayload } from 'payload'\n",
      })
    }
  }
  return applySplices(content, splices)
}

// --- <expr>.betterAuth.api.getSession (#70.2) -------------------------------

/** The receiver text when the callee is exactly `<expr>.betterAuth.api.getSession`. */
function betterAuthSessionReceiver(call: ts.CallExpression, source: ts.SourceFile): string | null {
  const callee = call.expression
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'getSession') {
    return null
  }
  const api = callee.expression
  if (!ts.isPropertyAccessExpression(api) || api.name.text !== 'api') {
    return null
  }
  const betterAuth = api.expression
  if (!ts.isPropertyAccessExpression(betterAuth) || betterAuth.name.text !== 'betterAuth') {
    return null
  }
  // Aliased bindings (`const auth = payload.betterAuth`) are never
  // rewritten — the rule matches only direct `.betterAuth.api` chains;
  // findManualSites reports the surviving accessor.
  return betterAuth.expression.getText(source)
}

/** The getSession argument text per #70: unwrap a lone `headers` object. */
function sessionArgsText(call: ts.CallExpression, source: ts.SourceFile): string {
  const arg = call.arguments[0]
  if (
    call.arguments.length >= 1 &&
    arg !== undefined &&
    ts.isObjectLiteralExpression(arg) &&
    arg.properties.length === 1
  ) {
    const prop = arg.properties[0]
    if (prop !== undefined) {
      if (ts.isPropertyAssignment(prop) && prop.name.getText(source) === 'headers') {
        return prop.initializer.getText(source)
      }
      if (ts.isShorthandPropertyAssignment(prop) && prop.name.text === 'headers') {
        return prop.name.getText(source)
      }
    }
  }
  return call.arguments.map((entry) => entry.getText(source)).join(', ')
}

function rewriteBetterAuthGetSession(content: string): string {
  const source = parse(content)
  const splices: Splice[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const receiver = betterAuthSessionReceiver(node, source)
      if (receiver !== null && awaitContext(node) !== 'sync-function') {
        splices.push({
          start: node.getStart(source),
          end: node.getEnd(),
          text: `(await authLinkServer(${receiver}).getSession(${sessionArgsText(node, source)}))`,
        })
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return applySplices(content, splices)
}

// --- toNextJsHandler (#70.3) ------------------------------------------------

const nextJsHandlerOutput =
  'export const GET = createRouteHandlers.GET\nexport const POST = createRouteHandlers.POST'

type NextJsHandlerImport = {
  readonly statement: ts.ImportDeclaration
  readonly element: ts.ImportSpecifier
  readonly local: string
}

function collectNextJsHandlerImports(source: ts.SourceFile): readonly NextJsHandlerImport[] {
  const imports: NextJsHandlerImport[] = []
  for (const statement of source.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      moduleSpecifierOf(statement) !== 'better-auth/next-js'
    ) {
      continue
    }
    const clause = statement.importClause
    if (
      clause === undefined ||
      clause.namedBindings === undefined ||
      !ts.isNamedImports(clause.namedBindings)
    ) {
      continue
    }
    for (const element of clause.namedBindings.elements) {
      const imported = (element.propertyName ?? element.name).text
      if (imported !== 'toNextJsHandler') {
        continue
      }
      imports.push({ statement, element, local: element.name.text })
    }
  }
  return imports
}

function rewriteNextJsHandler(content: string): string {
  const source = parse(content)
  const imports = collectNextJsHandlerImports(source)
  if (imports.length === 0) {
    return content
  }
  // The export-assignment shape stays textual (same output as #53),
  // now matching the aliased local name too.
  let current = content
  for (const imp of imports) {
    const pattern = new RegExp(
      `export\\s*\\{\\s*(\\w+)\\s+as\\s+GET\\s*,\\s*(\\w+)\\s+as\\s+POST\\s*\\}\\s*=\\s*${escapeRegExp(imp.local)}\\s*\\(\\s*payload\\.betterAuth\\s*\\)`,
      'g'
    )
    current = current.replace(pattern, nextJsHandlerOutput)
  }
  // The import rewrite runs on the rewritten content.
  const after = parse(current)
  const splices: Splice[] = []
  for (const imp of collectNextJsHandlerImports(after)) {
    if (soleNamedElement(imp.statement)) {
      splices.push({
        start: imp.statement.getStart(after),
        end: imp.statement.getEnd(),
        text: "import { createRouteHandlers } from '@payload-auth-link/next'",
      })
    } else {
      splices.push(removeElementSplice(imp.statement, imp.element, after))
      splices.push({
        start: imp.statement.getStart(after),
        end: imp.statement.getStart(after),
        text: "import { createRouteHandlers } from '@payload-auth-link/next'\n",
      })
    }
  }
  return applySplices(current, splices)
}

// --- rules -------------------------------------------------------------------

export const codemodRules: readonly CodemodRule[] = [
  {
    id: 'get-payload-auth',
    description: 'getPayloadAuth() -> getPayload({ config }), import -> payload',
    apply: rewritePayloadAuth,
  },
  {
    id: 'better-auth-get-session',
    description:
      'payload.betterAuth.api.getSession({ headers }) -> authLinkServer(payload).getSession(headers)',
    apply: rewriteBetterAuthGetSession,
  },
  {
    id: 'to-next-js-handler',
    description:
      'toNextJsHandler(payload.betterAuth) -> createRouteHandlers from @payload-auth-link/next',
    apply: rewriteNextJsHandler,
  },
]

/**
 * Report call sites the rules cannot fully rewrite (issue #70.4):
 * EVERY remaining `getPayloadAuth` reference (calls, type references,
 * the import itself), every surviving `payload.betterAuth` accessor
 * (including `.betterAuth.api.<method>` and `$context`), and every
 * `internalAdapter`. Nothing is silently ignored — the doctor counts
 * these references, so the codemod must account for them.
 */
export function findManualSites(content: string): readonly string[] {
  const source = parse(content)
  const manual: string[] = []
  const reportedLines = new Set<number>()
  const { imports, refs } = analyzePayloadAuth(content)
  for (const ref of refs) {
    if (ref.reason !== undefined) {
      manual.push(ref.reason)
      reportedLines.add(lineOf(source, ref.node))
    }
  }
  for (const imp of imports) {
    manual.push(
      `getPayloadAuth import (line ${lineOf(source, imp.statement)}) — replace with import { getPayload } from 'payload'`
    )
    reportedLines.add(lineOf(source, imp.statement))
  }
  const seenInternalsLines = new Set<number>()
  const visit = (node: ts.Node): void => {
    // A getPayloadAuth reference the import analysis did not cover (a
    // local binding, no payload-auth import) is still reported.
    if (
      ts.isIdentifier(node) &&
      node.text === 'getPayloadAuth' &&
      !reportedLines.has(lineOf(source, node))
    ) {
      manual.push(
        `getPayloadAuth reference (line ${lineOf(source, node)}) — rewrite by hand to await getPayload({ config })`
      )
      reportedLines.add(lineOf(source, node))
    }
    if (ts.isPropertyAccessExpression(node)) {
      const line = lineOf(source, node)
      if (node.name.text === 'betterAuth') {
        const parent = node.parent
        if (ts.isPropertyAccessExpression(parent) && parent.name.text === 'api') {
          const method = parent.parent
          if (
            ts.isPropertyAccessExpression(method) &&
            method.name.text === 'getSession' &&
            ts.isCallExpression(method.parent) &&
            awaitContext(method.parent) === 'sync-function'
          ) {
            manual.push(
              `getSession (line ${line}) — the enclosing function is not async: make it async and use await authLinkServer(...).getSession(...)`
            )
          } else {
            manual.push(
              `payload.betterAuth.api.<method> (line ${line}) — see the authLinkServer session API (#54)`
            )
          }
        } else {
          manual.push(
            `payload.betterAuth accessor (line ${line}) — see the authLinkServer session API (#54)`
          )
        }
      } else if (node.name.text === '$context') {
        seenInternalsLines.add(line)
        manual.push(
          `$context internals (line ${line}) — see the supported server session API (#54)`
        )
      } else if (node.name.text === 'internalAdapter' && !seenInternalsLines.has(line)) {
        manual.push(
          `internalAdapter (line ${line}) — Better Auth internals; see the supported server session API (#54)`
        )
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
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
  return { file, changed: current !== content, applied, manual, after: current }
}
