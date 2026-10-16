import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  chromium,
  request,
  type Browser,
  type BrowserContext,
  type FullConfig,
} from '@playwright/test'
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

/**
 * Pages whose first load pays a one-time dev-server cost: the example
 * home, both sign-in forms, and the Payload admin (its RSC environment
 * boots on the first admin request, and `@payloadcms/ui` is excluded
 * from Vite's dep optimizer, so its client modules transform on first
 * fetch).
 */
const warmUpPaths = ['/', '/sign-in', '/sign-in-authjs', '/admin/login']

/**
 * Load every cold surface once, sequentially, in a real browser before
 * any spec runs. On a fresh Vite dev server (TanStack Start) the first
 * browser loads race the cold pipeline: the dep optimizer settling its
 * first pass, the RSC environment booting, hundreds of on-demand
 * transforms. With two workers the first two admin loads
 * (`smoke.spec.ts`, `admin-provider-login.spec.ts`) landed in that
 * window concurrently, and WebKit reported a dropped module fetch as
 * "Importing a module script failed". Warm, the same loads are cache
 * hits. A page that still raised an error is loaded once more, so an
 * optimizer reload settles here instead of inside a spec. Harmless for
 * Next (it compiles the same routes on first hit).
 */
async function warmUp(baseURL: string): Promise<void> {
  const browser = await chromium.launch()
  try {
    const page = await browser.newPage({ baseURL })
    const errors: Error[] = []
    page.on('pageerror', (error) => errors.push(error))
    for (const path of warmUpPaths) {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        errors.length = 0
        await page.goto(path, { waitUntil: 'networkidle', timeout: 180_000 })
        if (errors.length === 0) {
          break
        }
      }
    }
  } finally {
    await browser.close()
  }
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
  // After the login, not before: the login's REST request boots Payload
  // in the request-handler environment first. Under TanStack Start the
  // admin page runs in a separate (RSC) Vite environment with its own
  // module instances but the same globally cached Payload instance; if
  // the admin boots Payload first, `authLinkServer(payload)` in the
  // request-handler routes (`/api/step-up`) misses its registry.
  await warmUp(baseURL)
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
