/**
 * TanStack Mongo parity runner: boots a per-run
 * `mongodb-memory-server` replset, hands its URI to the Playwright
 * TanStack mongo config, runs the specs, then stops the replset.
 * Extra CLI args pass through to Playwright
 * (`bun e2e/run-tanstack-mongo.mjs -- e2e/smoke.spec.ts`).
 */
import { spawn } from 'node:child_process'
import { MongoMemoryReplSet } from 'mongodb-memory-server'

// wiredTiger, not the ephemeralForTest default: it matches production
// lock/catalog behavior and avoids spurious WriteConflicts while
// Payload builds indexes on first touch.
const replset = await MongoMemoryReplSet.create({
  replSet: { count: 1, storageEngine: 'wiredTiger' },
})
const child = spawn(
  'bunx',
  ['playwright', 'test', '-c', 'e2e/playwright.tanstack-mongo.config.ts', ...process.argv.slice(2)],
  {
    env: { ...process.env, MONGODB_URI: replset.getUri('pal_e2e') },
    stdio: 'inherit',
  }
)
const code = await new Promise((resolve) => child.on('close', resolve))
await replset.stop()
process.exit(typeof code === 'number' ? code : 1)
