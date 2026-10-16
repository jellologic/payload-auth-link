/**
 * Payload-symbol inventory (Phase 3): every `payload` / `payload/shared`
 * import in shipped source sets this repo's real Payload floor — the
 * day a symbol appears that an older Payload lacks, that older version
 * is out no matter what the peer range claims (B4). The inventory is
 * pinned here so a new import fails CI and forces the question: is
 * this symbol available across the whole declared band? Verify against
 * the floor (see docs/compatibility.md), add a compatibility note for
 * the symbol, then update the pin.
 *
 * Scans shipped source only (`__tests__` excluded): test-only imports
 * run against the repo's own dev version, so they cannot break a
 * consumer on an older Payload.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..')
const PACKAGES = [
  'core',
  'web',
  'next',
  'tanstack-start',
  'plugin',
  'provider-better-auth',
  'provider-authjs',
] as const

const MODULE_PATTERN = /^payload(?:\/shared)?$/

function listSources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === '__tests__' || entry === 'dist') {
      continue
    }
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      listSources(full, out)
    } else if (/\.(ts|tsx)$/.test(entry)) {
      out.push(full)
    }
  }
  return out
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ')
}

function collectSymbols(packageName: string): readonly string[] {
  const srcDir = join(repoRoot, 'packages', packageName, 'src')
  const symbols = new Set<string>()
  for (const file of listSources(srcDir)) {
    const text = stripComments(readFileSync(file, 'utf8'))
    const namedImport = /import\s+(?:type\s+)?\{([^{}]*?)\}\s*from\s*'(payload(?:\/shared)?)'/g
    for (const match of text.matchAll(namedImport)) {
      if (!MODULE_PATTERN.test(match[2] ?? '')) {
        continue
      }
      for (const raw of (match[1] ?? '').split(',')) {
        const name = raw
          .trim()
          .replace(/^type\s+/, '')
          .replace(/\s+as\s+\w+$/, '')
          .trim()
        if (name !== '') {
          symbols.add(name)
        }
      }
    }
    const defaultImport = /import\s+(?:\*\s+as\s+\w+|\w+)\s+from\s*'payload(?:\/shared)?'/g
    for (const match of text.matchAll(defaultImport)) {
      symbols.add(`(default/namespace: ${match[1] ?? ''})`)
    }
  }
  return [...symbols].sort()
}

describe('payload import inventory (Phase 3)', () => {
  it('pins every payload / payload/shared symbol in shipped source', () => {
    const inventory: Record<string, readonly string[]> = {}
    for (const packageName of PACKAGES) {
      inventory[packageName] = collectSymbols(packageName)
    }
    // A new import lands here unsorted and the pin below fails. That
    // is the alarm: resolve the symbol against the declared Payload
    // band, note it in docs/compatibility.md, update this pin.
    expect(inventory).toEqual({
      core: [],
      web: [],
      next: [],
      'tanstack-start': [],
      plugin: [
        'APIError',
        'Access',
        'ArrayField',
        'AuthStrategy',
        'CheckboxField',
        'CollectionAfterChangeHook',
        'CollectionAfterDeleteHook',
        'CollectionBeforeChangeHook',
        'CollectionBeforeDeleteHook',
        'CollectionBeforeOperationHook',
        'CollectionBeforeValidateHook',
        'CollectionConfig',
        'Config',
        'DateField',
        'Endpoint',
        'Field',
        'FieldAccess',
        'FieldAccessArgs',
        'GlobalBeforeOperationHook',
        'GlobalConfig',
        'Payload',
        'PayloadRequest',
        'Plugin',
        'SelectField',
        'TextField',
        'ValidationError',
        'Where',
        'addDataAndFileToRequest',
      ],
      'provider-authjs': ['CollectionConfig', 'Field', 'Payload', 'Where'],
      'provider-better-auth': ['CollectionConfig', 'Field', 'Payload', 'Where'],
    })
  })
})
