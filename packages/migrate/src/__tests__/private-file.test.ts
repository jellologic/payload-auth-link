import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { writePrivateFile } from '../private-file.js'

describe('writePrivateFile', () => {
  it('creates the file owner-only', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'pal-private-')), 'export.jsonl')
    writePrivateFile(path, 'secret\n')
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(readFileSync(path, 'utf8')).toBe('secret\n')
  })

  it('tightens and replaces a pre-existing world-readable file', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'pal-private-')), 'manifest.json')
    writeFileSync(path, 'a much longer previous content\n')
    chmodSync(path, 0o644)
    writePrivateFile(path, 'new\n')
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(readFileSync(path, 'utf8')).toBe('new\n')
  })
})
