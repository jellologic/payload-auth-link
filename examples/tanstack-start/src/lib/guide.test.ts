/**
 * DX guard for docs/guide-tanstack-start.md: every package import in
 * the guide's snippets must name a real export of that barrel, so a
 * copy-pasted snippet never fails on a wrong import line.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const guide = readFileSync(
  new URL('../../../../docs/guide-tanstack-start.md', import.meta.url),
  'utf8'
)

/** Every `import { … } from '@payload-auth-link/<pkg>'` in the guide. */
function guideImports(): readonly { pkg: string; names: readonly string[] }[] {
  const pattern = /import\s*\{([^}]+)\}\s*from\s*'@payload-auth-link\/([a-z-]+)'/g
  return [...guide.matchAll(pattern)].map((match) => ({
    pkg: match[2] ?? '',
    names: (match[1] ?? '')
      .split(',')
      .map((name) => name.trim())
      .filter((name) => name !== ''),
  }))
}

/** The real barrels, resolved exactly as this adopter app resolves them. */
const barrels: Record<string, () => Promise<Record<string, unknown>>> = {
  'tanstack-start': () => import('@payload-auth-link/tanstack-start'),
  react: () => import('@payload-auth-link/react'),
}

describe('guide-tanstack-start.md snippets', () => {
  it('import only names the real barrels export', async () => {
    const imports = guideImports()
    expect(imports.map((entry) => entry.pkg)).toContain('react')
    for (const { pkg, names } of imports) {
      const load = barrels[pkg]
      expect(load, `no barrel mapped for @payload-auth-link/${pkg}`).toBeDefined()
      if (load === undefined) {
        continue
      }
      const barrel = await load()
      for (const name of names) {
        expect(barrel[name], `${name} from @payload-auth-link/${pkg}`).toBeDefined()
      }
    }
  })

  it('takes AuthLinkProvider from react, never the Start adapter', async () => {
    expect(guide).toContain("import { AuthLinkProvider } from '@payload-auth-link/react'")
    const adapter: Record<string, unknown> = await import('@payload-auth-link/tanstack-start')
    expect(adapter['AuthLinkProvider']).toBeUndefined()
  })

  it('does not install web directly (it arrives as a dependency)', () => {
    const install = /```bash\n(bun add[^`]+)```/.exec(guide)?.[1] ?? ''
    expect(install).toContain('@payload-auth-link/tanstack-start')
    expect(install).not.toContain('@payload-auth-link/web')
  })
})
