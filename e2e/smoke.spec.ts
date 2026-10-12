import { expect, test } from '@playwright/test'
import { gotoOwn, gotoSettled } from './helpers.js'

test('homepage renders', async ({ page }) => {
  await gotoOwn(page, '/')
  await expect(page.getByRole('heading', { name: /payload-auth-link/i })).toBeVisible()
})

test('admin serves login', async ({ page }) => {
  await gotoSettled(page, '/admin/login')
  await expect(page.getByLabel(/email/i)).toBeVisible()
})
