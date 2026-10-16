/**
 * `allowLocalCredentialsForLinkedDocs`: a Payload API key enabled
 * before the link is kept and keeps working (matrix row 10a opt-in).
 */
import { beforeAll, describe, expect, it } from 'vitest'
import {
  apiKeyHeader,
  boot,
  documentWithKey,
  keyIndexed,
  link,
  meUserId,
  rest,
  type Instance,
} from './prelink-api-key-harness.js'

let optedIn: Instance

beforeAll(async () => {
  optedIn = await boot('prelink-api-key-opted-in', true)
}, 60_000)

describe('allowLocalCredentialsForLinkedDocs keeps the API key', () => {
  it('the pre-link key keeps working after the link', async () => {
    const email = 'kept@prelink-api-key.test'
    const apiKey = 'kept-api-key-0123456789abcdef0123'
    const id = await documentWithKey(optedIn, email, apiKey)
    await link(optedIn, email, 'stub-kept')
    const authorization = apiKeyHeader(apiKey)
    expect(await keyIndexed(optedIn, apiKey)).toBe(true)
    expect((await rest(optedIn, 'GET', `/users/${id}`, { authorization })).status).toBe(200)
    const patch = await rest(optedIn, 'PATCH', `/users/${id}`, { authorization, body: {} })
    expect(patch.status).toBe(200)
    expect(meUserId(await rest(optedIn, 'GET', '/users/me', { authorization }))).toBe(id)
  })
})
