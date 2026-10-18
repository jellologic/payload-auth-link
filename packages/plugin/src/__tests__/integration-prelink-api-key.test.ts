/**
 * Payload API keys enabled on a document BEFORE a provider identity
 * links to it (credential-path matrix row 10a, docs/security-model.md).
 * Linking clears the key, and the provider-owned gate refuses any key
 * on a linked document (one re-enabled after the link included).
 * The `allowLocalCredentialsForLinkedDocs` opt-in is walked in
 * `integration-prelink-api-key-opt-in.test.ts`.
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
  usersGrants,
  type Instance,
} from './prelink-api-key-harness.js'

let strict: Instance

beforeAll(async () => {
  strict = await boot('prelink-api-key-strict', false)
}, 60_000)

describe('a Payload API key enabled before the link (default)', () => {
  const email = 'keyed@prelink-api-key.test'
  const apiKey = 'pre-link-api-key-0123456789abcdef'
  const authorization = apiKeyHeader(apiKey)
  let id = ''

  beforeAll(async () => {
    id = await documentWithKey(strict, email, apiKey)
    // Before the link the key is a working credential for its document.
    expect((await rest(strict, 'GET', `/users/${id}`, { authorization })).status).toBe(200)
    expect(meUserId(await rest(strict, 'GET', '/users/me', { authorization }))).toBe(id)
    expect(usersGrants(await rest(strict, 'GET', '/access', { authorization })).update).toBe(true)
    await link(strict, email, 'stub-keyed')
  })

  it('is refused (403) on read, update, and list after the link', async () => {
    expect((await rest(strict, 'GET', `/users/${id}`, { authorization })).status).toBe(403)
    const patch = await rest(strict, 'PATCH', `/users/${id}`, {
      authorization,
      body: { email: 'moved@prelink-api-key.test' },
    })
    expect(patch.status).toBe(403)
    expect((await rest(strict, 'GET', '/users', { authorization })).status).toBe(403)
    const doc = await strict.payload.findByID({ collection: 'users', id, overrideAccess: true })
    expect(doc.email).toBe(email)
  })

  it('/users/me resolves no user and /access carries no grant', async () => {
    // The cleared key no longer authenticates: `me` answers no user.
    const me = await rest(strict, 'GET', '/users/me', { authorization })
    expect(me.status).toBe(200)
    expect(meUserId(me)).toBeNull()
    const access = await rest(strict, 'GET', '/access', { authorization })
    expect(access.status).toBe(200)
    const grants = usersGrants(access)
    expect(grants.read).toBeFalsy()
    expect(grants.update).toBeFalsy()
  })

  it('linking cleared the key from the document', async () => {
    expect(await keyIndexed(strict, apiKey)).toBe(false)
  })

  it('a key re-enabled after the link is refused by the provider-owned gate', async () => {
    const reEnabled = 're-enabled-api-key-0123456789abcdef'
    await strict.payload.update({
      collection: 'users',
      id,
      data: { enableAPIKey: true, apiKey: reEnabled },
      overrideAccess: true,
    })
    expect(await keyIndexed(strict, reEnabled)).toBe(true)
    const auth = { authorization: apiKeyHeader(reEnabled) }
    // The key resolves no user at authentication (GHSA-mjvh): every
    // request it signs is anonymous, so the default access denies it.
    expect((await rest(strict, 'GET', `/users/${id}`, auth)).status).toBe(403)
    expect((await rest(strict, 'PATCH', `/users/${id}`, { ...auth, body: {} })).status).toBe(403)
    expect((await rest(strict, 'GET', '/users', auth)).status).toBe(403)
    const me = await rest(strict, 'GET', '/users/me', auth)
    expect(me.status).toBe(200)
    expect(meUserId(me)).toBeNull()
    const access = await rest(strict, 'GET', '/access', auth)
    expect(access.status).toBe(200)
    const grants = usersGrants(access)
    expect(grants.read).toBeFalsy()
    expect(grants.update).toBeFalsy()
  })

  it('an unlinked document keeps its API key', async () => {
    const plainEmail = 'plain@prelink-api-key.test'
    const plainKey = 'unlinked-api-key-0123456789abcdef'
    const plainId = await documentWithKey(strict, plainEmail, plainKey)
    const auth = { authorization: apiKeyHeader(plainKey) }
    expect((await rest(strict, 'GET', `/users/${plainId}`, auth)).status).toBe(200)
    expect((await rest(strict, 'PATCH', `/users/${plainId}`, { ...auth, body: {} })).status).toBe(
      200
    )
    expect(meUserId(await rest(strict, 'GET', '/users/me', auth))).toBe(plainId)
  })
})
