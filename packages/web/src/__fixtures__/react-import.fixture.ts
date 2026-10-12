/**
 * Boundary-violation fixture for the web core-only lint block (ARCH-2):
 * a React import from web sources must fail `bun run lint`.
 *
 * Deliberately red: ignored by the normal lint run (root
 * `eslint.config.mjs` ignores), excluded from `tsc -b` (this package's
 * tsconfig) and coverage (root `vitest.config.ts`). Executed
 * explicitly via `eslint --no-ignore` by
 * `../__tests__/lint-boundary.test.ts`, which asserts the failure and
 * the rule name.
 */
import { createElement } from 'react'

export const marker = createElement('span')
