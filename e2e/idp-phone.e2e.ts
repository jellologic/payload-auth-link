import { expect, test } from '@playwright/test'
import {
  asAdmin,
  payloadUsersByEmail,
  readSession,
  readSmsCode,
  uniqueEmail,
  uniquePhone,
  wrongCode,
} from './idp-helpers.js'
import { gotoOwn, pageFetch, signUpVerified } from './helpers.js'

/**
 * Phone sign-in (CAP-9) on the external-IdP variant: Better Auth's
 * `phoneNumber` plugin with `sendOTP` writing to the example's dev SMS
 * outbox (`/api/dev-sms`, 404 in production) instead of an SMS gateway.
 *
 * An existing, email-verified user verifies a phone number; a later
 * phone-OTP sign-in resolves to the SAME Payload user (the provider
 * session carries that user's verified email, and the verified phone
 * claim syncs onto the Payload user). Wrong codes sign nobody in.
 *
 * The phone-only linking branch (`linkingPolicy:
 * 'verified-email-or-phone'`) needs every provider to declare `phone`,
 * and the examples also register Auth.js, which cannot: it stays
 * pinned by the plugin/core integration tests.
 */

test('a verified phone signs in to the existing user; wrong codes are refused', async ({
  page,
  browser,
  baseURL,
}) => {
  const email = uniqueEmail('phone')
  const phone = uniquePhone()

  const userId = await test.step('sign up and verify a phone number', async () => {
    await gotoOwn(page, '/sign-in')
    const { userId: id } = await signUpVerified(page.request, email)
    const sentAt = Date.now()
    const sent = await pageFetch(page, 'POST', '/api/auth/phone-number/send-otp', {
      phoneNumber: phone,
    })
    expect(sent.status, JSON.stringify(sent.body)).toBe(200)
    const code = await readSmsCode(page.request, phone, sentAt)

    const wrong = await pageFetch(page, 'POST', '/api/auth/phone-number/verify', {
      phoneNumber: phone,
      code: wrongCode(code),
      updatePhoneNumber: true,
    })
    expect(wrong.status, JSON.stringify(wrong.body)).toBe(400)

    const verified = await pageFetch(page, 'POST', '/api/auth/phone-number/verify', {
      phoneNumber: phone,
      code,
      updatePhoneNumber: true,
    })
    expect(verified.status, JSON.stringify(verified.body)).toBe(200)
    // The session refresh syncs the verified phone claim to Payload.
    const session = await readSession(page)
    expect(String(session.user?.id)).toBe(id)
    return id
  })

  await test.step('the Payload user carries the verified phone', async () => {
    const users = await asAdmin(browser, baseURL, (adminPage) =>
      payloadUsersByEmail(adminPage, email)
    )
    expect(users).toHaveLength(1)
    expect(users[0]?.phone).toBe(phone)
  })

  await test.step('signed out, a wrong code does not sign in', async () => {
    const out = await pageFetch(page, 'DELETE', '/api/auth-link/session')
    expect(out.status).toBe(200)
    await page.context().clearCookies()
    await gotoOwn(page, '/sign-in')
    const sentAt = Date.now()
    const sent = await pageFetch(page, 'POST', '/api/auth/phone-number/send-otp', {
      phoneNumber: phone,
    })
    expect(sent.status).toBe(200)
    const code = await readSmsCode(page.request, phone, sentAt)
    const wrong = await pageFetch(page, 'POST', '/api/auth/phone-number/verify', {
      phoneNumber: phone,
      code: wrongCode(code),
    })
    expect(wrong.status, JSON.stringify(wrong.body)).toBe(400)
    expect((await readSession(page)).status).toBe(401)

    const right = await pageFetch(page, 'POST', '/api/auth/phone-number/verify', {
      phoneNumber: phone,
      code,
    })
    expect(right.status, JSON.stringify(right.body)).toBe(200)
  })

  await test.step('the phone sign-in resolves to the same Payload user', async () => {
    const session = await readSession(page)
    expect(session.status).toBe(200)
    expect(String(session.user?.id)).toBe(userId)
    expect(session.user?.email).toBe(email)
  })
})
