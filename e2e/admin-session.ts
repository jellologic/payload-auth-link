import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { request, type Browser, type BrowserContext, type FullConfig } from '@playwright/test'
import { DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD } from './dev-admin.js'

/**
 * One seeded-admin login per run, shared by every spec that needs admin
 * rights. Payload's login read-modify-writes the user's `sessions`
 * array, so two concurrent logins of the same user can drop one
 * another's session (observed in CI as a spurious 403 and an empty
 * admin list, hidden only by retries). Specs therefore never log the
 * admin in themselves — except `users-admin.spec.ts`, which keeps the one
 * real UI-login path and is safe because nothing else logs in
 * concurrently.
 */
const authDir = join(dirname(fileURLToPath(import.meta.url)), '.auth')

/** Storage-state file for one server (configs differ by port). */
export function adminStatePath(baseURL: string): string {
  return join(authDir, `admin-${new URL(baseURL).port}.json`)
}

function requireBaseURL(baseURL: string | undefined): string {
  if (baseURL === undefined) {
    throw new Error('admin session needs a configured baseURL')
  }
  return baseURL
}

/** Playwright `globalSetup`: runs once, after the web server is up. */
export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL = requireBaseURL(config.projects[0]?.use.baseURL)
  const api = await request.newContext({ baseURL })
  try {
    const login = await api.post('/api/users/login', {
      data: { email: DEV_ADMIN_EMAIL, password: DEV_ADMIN_PASSWORD },
    })
    if (!login.ok()) {
      throw new Error(`seeded admin login failed: ${login.status()} ${await login.text()}`)
    }
    mkdirSync(authDir, { recursive: true })
    await api.storageState({ path: adminStatePath(baseURL) })
  } finally {
    await api.dispose()
  }
}

/** A fresh browser context already signed in as the seeded admin. */
export function adminContext(
  browser: Browser,
  baseURL: string | undefined
): Promise<BrowserContext> {
  const origin = requireBaseURL(baseURL)
  // `browser.newContext` does not inherit the project's `use`: pass the
  // baseURL so relative navigations resolve.
  return browser.newContext({ baseURL: origin, storageState: adminStatePath(origin) })
}
