/**
 * DX guard for the per-package READMEs (the npm landing pages): every
 * `import { … } from '@payload-auth-link/<pkg>'` in a README snippet must
 * name a real export of that package's barrel, so a copy-pasted snippet
 * never fails on its import line. Barrels load from source.
 */
import { readFileSync } from 'node:fs'
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

const barrels: Record<string, () => Promise<Record<string, unknown>>> = {
  core: () => import('../../../packages/core/src/index.js'),
  web: () => import('../../../packages/web/src/index.js'),
  react: () => import('../../../packages/react/src/index.js'),
  plugin: () => import('../../../packages/plugin/src/index.js'),
  next: () => import('../../../packages/next/src/index.js'),
  'tanstack-start': () => import('../../../packages/tanstack-start/src/index.js'),
  'provider-better-auth': () => import('../../../packages/provider-better-auth/src/index.js'),
  'provider-authjs': () => import('../../../packages/provider-authjs/src/index.js'),
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
      const load = barrels[pkg]
      expect(load, `no barrel for @payload-auth-link/${pkg}`).toBeDefined()
      if (load === undefined) {
        continue
      }
      const barrel = await load()
      for (const imported of (match[1] ?? '').split(',').map((part) => part.trim())) {
        if (imported !== '') {
          expect(barrel[imported], `${imported} from @payload-auth-link/${pkg}`).toBeDefined()
        }
      }
    }
  })
})
