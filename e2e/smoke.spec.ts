import { expect, test } from '@playwright/test'
import { gotoOwn, gotoSettled } from './helpers.js'

test('homepage renders', async ({ page }) => {
  await gotoOwn(page, '/')
  await expect(page.getByRole('heading', { name: /payload-auth-link/i })).toBeVisible()
})

test('admin serves login', async ({ page }) => {
  await gotoSettled(page, '/admin/login')
  // The provider-backed login view (#55/#72) renders BOTH forms.
  await expect(page.getByRole('heading', { name: 'Provider sign-in' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Break-glass local sign-in' })).toBeVisible()
  await expect(
    page.locator('form', { hasText: 'Provider sign-in' }).getByLabel(/email/i)
  ).toBeVisible()
})
