/**
 * DX guard for the per-package READMEs (the npm landing pages): every
 * `import { … } from '@payload-auth-link/<pkg>'` in a README snippet must
 * name a real export of that package's barrel, so a copy-pasted snippet
 * never fails on its import line. Barrels load from source.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = new URL('../../../', import.meta.url)
const packages = [
  'core',
  'web',
  'react',
  'plugin',
  'next',
  'tanstack-start',
  'provider-better-auth',
  'provider-authjs',
] as const

/**
 * Load a package barrel from source. The specifier is computed on
 * purpose: a literal `import('../../../packages/…/src/index.js')` pulls
 * every package source into this app's type program, where a generated
 * `payload-types.ts` (written by `next dev`) narrows Payload's slugs and
 * fails sources written against the generic types. The sources are
 * type-checked by the root `typecheck`; here they are only executed.
 */
function loadBarrel(name: string): Promise<Record<string, unknown>> {
  const path = fileURLToPath(new URL(`packages/${name}/src/index.ts`, root))
  return import(/* @vite-ignore */ path) as Promise<Record<string, unknown>>
}

function isPackage(name: string): name is (typeof packages)[number] {
  return (packages as readonly string[]).includes(name)
}

function readme(name: string): string {
  return readFileSync(new URL(`packages/${name}/README.md`, root), 'utf8')
}

describe('package READMEs', () => {
  it.each(packages)('%s README names its package and imports only real exports', async (name) => {
    const text = readme(name)
    expect(text.startsWith(`# @payload-auth-link/${name}\n`)).toBe(true)
    const pattern = /import\s*\{([^}]+)\}\s*from\s*'@payload-auth-link\/([a-z-]+)'/g
    for (const match of text.matchAll(pattern)) {
      const pkg = match[2] ?? ''
      expect(isPackage(pkg), `no barrel for @payload-auth-link/${pkg}`).toBe(true)
      if (!isPackage(pkg)) {
        continue
      }
      const barrel = await loadBarrel(pkg)
      for (const imported of (match[1] ?? '').split(',').map((part) => part.trim())) {
        if (imported !== '') {
          expect(barrel[imported], `${imported} from @payload-auth-link/${pkg}`).toBeDefined()
        }
      }
    }
  })
})
