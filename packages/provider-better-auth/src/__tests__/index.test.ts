import { describe, expect, it } from 'vitest'
import { getBetterAuthSessionCookieNames } from '../index.js'

describe('provider-better-auth entrypoint', () => {
  it('serves the session cookie-name contract through the barrel', () => {
    expect(getBetterAuthSessionCookieNames({}, { nodeEnv: 'test' })).toContain(
      'better-auth.session_token'
    )
  })
})
