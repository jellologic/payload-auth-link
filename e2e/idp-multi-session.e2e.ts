import { expect, test } from '@playwright/test'
import { readSession, signUpInPage, uniqueEmail } from './idp-helpers.js'
import { gotoOwn, pageFetch } from './helpers.js'

/**
 * Multi-session (CAP-13b) on the external-IdP variant: Better Auth's
 * `multiSession` plugin keeps several accounts signed in in one
 * browser. The plugin session follows the ACTIVE account, switching
 * changes it, and the plugin's sign-out revokes EVERY device session
 * server-side — replaying the old cookies afterwards gets nothing.
 */
type DeviceSession = { session: { token: string }; user: { email: string } }

async function deviceSessions(page: Parameters<typeof pageFetch>[0]): Promise<DeviceSession[]> {
  const listed = await pageFetch(page, 'GET', '/api/auth/multi-session/list-device-sessions')
  if (listed.status !== 200 || !Array.isArray(listed.body)) {
    return []
  }
  return listed.body as DeviceSession[]
}

test('two accounts in one browser: switch the active one, sign-out clears both', async ({
  page,
  browser,
  baseURL,
}) => {
  const first = uniqueEmail('multi-a')
  const second = uniqueEmail('multi-b')

  const ids = await test.step('sign two accounts in, one after the other', async () => {
    await gotoOwn(page, '/sign-in')
    const a = await signUpInPage(page, first)
    const b = await signUpInPage(page, second)
    const listed = await deviceSessions(page)
    expect(listed.map((entry) => entry.user.email).sort()).toEqual([first, second].sort())
    // The newest sign-in is active.
    const session = await readSession(page)
    expect(session.user?.email).toBe(second)
    return { a, b }
  })

  await test.step('switching the active account switches the Payload user', async () => {
    const target = (await deviceSessions(page)).find((entry) => entry.user.email === first)
    if (target === undefined) {
      throw new Error('first account is not among the device sessions')
    }
    const switched = await pageFetch(page, 'POST', '/api/auth/multi-session/set-active', {
      sessionToken: target.session.token,
    })
    expect(switched.status, JSON.stringify(switched.body)).toBe(200)
    const session = await readSession(page)
    expect(session.user?.email).toBe(first)
    expect(String(session.user?.id)).toBe(ids.a)
    await gotoOwn(page, '/account')
    await expect(page.getByTestId('account-email')).toContainText(first, { timeout: 30_000 })
  })

  await test.step('sign-out revokes every device session, not just the active one', async () => {
    const before = await page.context().cookies()
    const out = await pageFetch(page, 'DELETE', '/api/auth-link/session')
    expect(out.status).toBe(200)
    expect((await readSession(page)).status).toBe(401)
    expect(await deviceSessions(page)).toEqual([])

    // Replay every cookie the browser held before signing out.
    const replay = await browser.newContext({ baseURL: baseURL ?? '' })
    try {
      await replay.addCookies(before)
      const replayPage = await replay.newPage()
      await gotoOwn(replayPage, '/sign-in')
      expect((await readSession(replayPage)).status).toBe(401)
      expect(await deviceSessions(replayPage)).toEqual([])
    } finally {
      await replay.close()
    }
  })
})
