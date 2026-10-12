/**
 * Build `llms.txt` (curated index) and `llms-full.txt` (full text) from
 * the docs tree, so agent artifacts can't drift from the guides.
 *
 * Run: `bun run docs:llms`.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const read = (path) => readFileSync(join(root, path), 'utf8').trim()

const summary = `payload-auth-link: a hexagonal ports/adapters Payload CMS auth plugin.
Identity providers (Better Auth, Auth.js) are swappable adapters behind
IdentityProviderPort; users stay first-class Payload documents. First-class
Next.js (Payload v3) and TanStack Start (Payload v4) adapters share one
framework-free web core. ESM-only, strict TypeScript, Result-based errors.
Example apps at examples/basic and examples/tanstack-start; 24 Playwright
specs green per suite across SQLite, Postgres, and Mongo on both frameworks
(SQLite suites in Chromium, Firefox, and WebKit).`

const guides = [
  [
    'docs/getting-started.md',
    'Four-edit drop-in: install, engine, plugin, routes+UI (Better Auth path).',
  ],
  ['docs/tour.md', 'File-by-file walkthrough of the reference example + screenshots.'],
  ['docs/concepts.md', 'Ports/adapters, JIT linking, verification gating, session flow, logout.'],
  [
    'docs/guide-better-auth.md',
    'Better Auth provider: secure defaults, passthrough, cookie names.',
  ],
  [
    'docs/guide-authjs.md',
    'Auth.js provider: credentials service, signup, JWT sessions, 302 contract.',
  ],
  [
    'docs/guide-tanstack-start.md',
    'TanStack Start adapter (Payload v4): mounts, middleware, loaders, guards.',
  ],
  ['docs/compatibility.md', 'Validated versions, databases, runtimes, ESM-only policy.'],
  ['docs/troubleshooting.md', 'Observed failure modes and fixes.'],
  ['docs/upgrading.md', 'Versioning policy and migration notes.'],
  ['docs/MISSION.md', 'Why the project exists; provider roadmap; non-goals.'],
  ['docs/DNA.md', 'Engineering constitution: architecture, guardrails, testing, security.'],
  ['docs/PLAN.md', 'Implementation plan with phase evidence.'],
  ['docs/PLAN-TANSTACK.md', 'TanStack Start support plan with phase evidence.'],
  [
    'docs/PLAN-CAPABILITIES.md',
    'Auth capabilities plan (MFA, passkeys, OAuth, magic link, orgs…) across both providers.',
  ],
  ['AGENTS.md', 'Agent working agreement for this repo.'],
  ['CONTRIBUTING.md', 'Setup, PR rules, release process.'],
  ['SECURITY.md', 'Security policy.'],
]

const keyFiles = [
  ['packages/core/src/ports.ts', 'Port interfaces: the hexagonal seams.'],
  ['packages/plugin/src/options.ts', 'Plugin options shape.'],
  ['packages/plugin/src/session.ts', 'Session bridge: providers to Payload users.'],
  ['packages/provider-better-auth/src/engine.ts', 'Better Auth composition root.'],
  ['packages/provider-authjs/src/engine.ts', 'Auth.js composition root.'],
  ['examples/basic/payload.config.ts', 'Reference plugin wiring.'],
  ['examples/basic/lib/auth.ts', 'Reference Better Auth engine.'],
  ['examples/basic/lib/authjs.ts', 'Reference Auth.js engine + credentials.'],
]

const llms = [
  '# payload-auth-link',
  '',
  `> ${summary.split('\n').join(' ')}`,
  '',
  '## Guides',
  '',
  ...guides.map(([path, blurb]) => `- [${path}](./${path}): ${blurb}`),
  '',
  '## Key source files',
  '',
  ...keyFiles.map(([path, blurb]) => `- [${path}](./${path}): ${blurb}`),
  '',
  '## API reference',
  '',
  '- Run `bun run docs:api` to generate typedoc HTML at `docs/api/` (gitignored).',
  '',
]
writeFileSync(join(root, 'llms.txt'), `${llms.join('\n')}\n`)

const full = [
  '# payload-auth-link (full)',
  '',
  `> ${summary.split('\n').join(' ')}`,
  '',
  ...guides.flatMap(([path]) => [`---`, ``, `<!-- ${path} -->`, ``, read(path), ``]),
]
writeFileSync(join(root, 'llms-full.txt'), `${full.join('\n')}\n`)
console.log('wrote llms.txt and llms-full.txt')
