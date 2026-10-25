/**
 * The direct-deps port facts (GHSA-hfm3 / issue #157): the passthrough
 * on `createBetterAuthProvider` and
 * `createBetterAuthProviderFromUnknown` — the engine-derived path is
 * pinned in `engine.test.ts`; direct users (a custom engine fronting
 * the port by hand) set the same facts honestly.
 */
import { describe, expect, it } from 'vitest'
import { createBetterAuthProvider, createBetterAuthProviderFromUnknown } from '../port.js'

const cookieNames = ['better-auth.session_token']

function fakeAuth(): Parameters<typeof createBetterAuthProvider>[0]['auth'] {
  return {
    api: { getSession: () => Promise.resolve(null) },
    $context: Promise.resolve({ internalAdapter: {} }),
  } as unknown as Parameters<typeof createBetterAuthProvider>[0]['auth']
}

describe('direct-deps port facts', () => {
  it('createBetterAuthProvider passes the adopted slugs and the magic-link fact through', () => {
    const port = createBetterAuthProvider({
      auth: fakeAuth(),
      sessionCookieNames: cookieNames,
      adoptedCollections: ['users', 'sessions'],
      secretCollections: ['sessions'],
      magicLinkEnabled: true,
    })
    expect(port.adoptedCollections).toEqual(['users', 'sessions'])
    expect(port.secretCollections).toEqual(['sessions'])
    expect(port.magicLinkEnabled).toBe(true)
  })

  it('absent facts stay absent', () => {
    const port = createBetterAuthProvider({
      auth: fakeAuth(),
      sessionCookieNames: cookieNames,
    })
    expect(port.adoptedCollections).toBeUndefined()
    expect(port.secretCollections).toBeUndefined()
    expect(port.magicLinkEnabled).toBeUndefined()
  })

  it('createBetterAuthProviderFromUnknown passes the adopted slugs through', () => {
    const port = createBetterAuthProviderFromUnknown(
      fakeAuth(),
      cookieNames,
      undefined,
      undefined,
      {
        adoptedCollections: ['ba_sessions'],
        secretCollections: ['ba_sessions', 'ba_verifications'],
        socialProviders: ['google'],
      }
    )
    expect(port.adoptedCollections).toEqual(['ba_sessions'])
    expect(port.secretCollections).toEqual(['ba_sessions', 'ba_verifications'])
    expect(port.socialProviders).toEqual(['google'])
    expect(port.magicLinkEnabled).toBeUndefined()
  })
})
