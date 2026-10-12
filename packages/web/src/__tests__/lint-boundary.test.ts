/**
 * Boundary proof for the web core-only lint block (ARCH-2). Runs the
 * real root ESLint config explicitly against the violation fixture
 * (which the normal `bun run lint` ignores) and asserts the run fails
 * on `no-restricted-imports` with the web message — not on a missing
 * file, a crash, or any other rule.
 */
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const rootDir = fileURLToPath(new URL('../../../..', import.meta.url))
const eslintBin = join(rootDir, 'node_modules', 'eslint', 'bin', 'eslint.js')
const fixture = join('packages', 'web', 'src', '__fixtures__', 'react-import.fixture.ts')

type ExecFileFailure = {
  readonly status: number | null
  readonly stdout: unknown
  readonly stderr: unknown
}

function isExecFileFailure(error: unknown): error is ExecFileFailure {
  return (
    typeof error === 'object' &&
    error !== null &&
    'status' in error &&
    'stdout' in error &&
    'stderr' in error
  )
}

function toText(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function runFixtureLint(): { status: number | null; output: string } {
  try {
    execFileSync(process.execPath, [eslintBin, '--no-ignore', fixture], {
      cwd: rootDir,
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 170_000,
    })
    return { status: 0, output: '' }
  } catch (error) {
    if (!isExecFileFailure(error)) {
      throw error
    }
    return { status: error.status, output: `${toText(error.stdout)}\n${toText(error.stderr)}` }
  }
}

describe('web lint boundary', () => {
  it('fails lint on a web-to-react import', () => {
    expect(existsSync(join(rootDir, fixture)), 'lint fixture exists').toBe(true)
    expect(existsSync(eslintBin), 'eslint bin resolves from the repo root').toBe(true)

    const { status, output } = runFixtureLint()

    expect(status, `eslint must reject the web-to-react fixture, got:\n${output}`).not.toBe(0)
    expect(output).toContain('no-restricted-imports')
    expect(output).toContain('web is framework-free')
  }, 180_000)
})
