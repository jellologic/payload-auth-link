import { expect, test } from '@playwright/test'
import { DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD } from './dev-admin.js'

// SEC-7: the seed-gate config boots each example on a fresh database
// WITHOUT `ALLOW_DEV_ADMIN_SEED`. The dev admin must not exist (Payload
// login 401s), while the app itself stays healthy (home 200s). Matched
// only by `playwright.seed-gate.config.ts` — the six matrix configs set
// the flag and seed the admin.
test('fresh database without the seed flag has no dev admin', async ({ page }) => {
  const home = await page.request.get('/')
  expect(home.ok()).toBe(true)

  const login = await page.request.post('/api/users/login', {
    data: { email: DEV_ADMIN_EMAIL, password: DEV_ADMIN_PASSWORD },
  })
  expect(login.status()).toBe(401)
})
