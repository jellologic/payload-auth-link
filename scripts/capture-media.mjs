/**
 * Capture docs media from the example app: boots `dev:example` on a
 * scratch port, screenshots the key flows, tears down. Output:
 * `docs/media/*.png` (referenced by the guides).
 *
 * Run: `bun run docs:media` (builds first).
 */
import { spawn } from 'node:child_process'
import { mkdirSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from '@playwright/test'
// Same seeded-admin identity as the e2e harness (SEC-7: the example seeds
// an admin only behind the explicit dev-only flag + env password).
import { DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD, DEV_ADMIN_SEED_ENV } from '../e2e/dev-admin.ts'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const media = join(root, 'docs', 'media')
mkdirSync(media, { recursive: true })

// Fresh database for clean screenshots (same as the e2e webServer).
for (const name of ['payload.db', 'payload.db-journal']) {
  try {
    rmSync(join(root, 'examples', 'basic', name))
  } catch {
    // missing is fine
  }
}

const app = 'http://localhost:3100'
const server = spawn('bun', ['run', 'dev'], {
  cwd: join(root, 'examples', 'basic'),
  env: { ...process.env, ...DEV_ADMIN_SEED_ENV, EXAMPLE_BASE_URL: app },
  stdio: 'pipe',
})
for (let i = 0; i < 120; i++) {
  try {
    const res = await fetch(app)
    if (res.ok) break
  } catch {
    // not up yet
  }
  await new Promise((r) => setTimeout(r, 1000))
}

try {
  const browser = await chromium.launch()
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } })

  await page.goto(`${app}/`)
  await page.screenshot({ path: join(media, '01-home.png') })

  await page.goto(`${app}/sign-in`)
  await page.screenshot({ path: join(media, '02-sign-in.png') })

  await page.goto(`${app}/sign-in-authjs`)
  await page.screenshot({ path: join(media, '03-sign-in-authjs.png') })

  const email = `media-${Date.now()}@example.com`
  await page.goto(`${app}/sign-in`)
  await page.getByRole('button', { name: /need an account/i }).click()
  await page.getByLabel(/email/i).fill(email)
  await page.getByLabel(/password/i).fill('media-password-1')
  await page.getByRole('button', { name: /create account/i }).click()
  await page.getByTestId('account-email').waitFor({ timeout: 30_000 })
  await page.screenshot({ path: join(media, '04-account.png') })

  await page.context().clearCookies()
  await page.goto(`${app}/admin/login`)
  await page.getByLabel(/email/i).fill(DEV_ADMIN_EMAIL)
  await page.getByRole('textbox', { name: /password/i }).fill(DEV_ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Login', exact: true }).click()
  await page.waitForURL('**/admin', { timeout: 15000 })
  await page.goto(`${app}/admin/collections/users`)
  await page.getByRole('cell', { name: 'admin' }).waitFor({ timeout: 15000 })
  await page.screenshot({ path: join(media, '05-admin-users.png') })

  await browser.close()
  console.log('media captured to docs/media/')
} finally {
  server.kill()
}
