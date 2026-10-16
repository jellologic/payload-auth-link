import { closeSync, fchmodSync, ftruncateSync, openSync, writeSync } from 'node:fs'

/**
 * Write `content` to `path` readable by the owner only (0600). The
 * mode is tightened on the open descriptor BEFORE any content lands, so
 * a pre-existing world-readable file (an older kit's manifest, a
 * reused `--out` path) never holds the new content with its old mode.
 */
export function writePrivateFile(path: string, content: string): void {
  const fd = openSync(path, 'a', 0o600)
  try {
    fchmodSync(fd, 0o600)
    ftruncateSync(fd, 0)
    writeSync(fd, content, 0)
  } finally {
    closeSync(fd)
  }
}
