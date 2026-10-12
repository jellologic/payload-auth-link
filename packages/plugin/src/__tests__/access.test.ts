import { describe, expect, it } from 'vitest'
import { forbidden, isSameOrigin, passesCsrf, unauthorized } from '../access.js'

const baseUrl = 'http://auth-link.test'

describe('isSameOrigin', () => {
  it('compares origins strictly', () => {
    expect(isSameOrigin('http://auth-link.test/login', baseUrl)).toBe(true)
    expect(isSameOrigin('https://auth-link.test/', baseUrl)).toBe(false)
    expect(isSameOrigin('http://evil.test/', baseUrl)).toBe(false)
    expect(isSameOrigin('not-a-url', baseUrl)).toBe(false)
    expect(isSameOrigin('http://auth-link.test/', 'not-a-url')).toBe(false)
  })
})

describe('passesCsrf', () => {
  it('accepts the custom header', () => {
    expect(passesCsrf(new Headers({ 'x-auth-link-csrf': '1' }), baseUrl)).toBe(true)
  })

  it('accepts a matching Origin', () => {
    expect(passesCsrf(new Headers({ origin: 'http://auth-link.test' }), baseUrl)).toBe(true)
  })

  it('fails closed otherwise', () => {
    expect(passesCsrf(new Headers(), baseUrl)).toBe(false)
    expect(passesCsrf(new Headers({ origin: 'https://evil.test' }), baseUrl)).toBe(false)
    expect(passesCsrf(new Headers({ 'x-auth-link-csrf': 'yes' }), baseUrl)).toBe(false)
  })
})

describe('error responses', () => {
  it('uses 401 and 403 with bodies', async () => {
    expect(unauthorized().status).toBe(401)
    expect(forbidden().status).toBe(403)
    expect(await unauthorized().json()).toEqual({ error: 'authentication required' })
  })
})
