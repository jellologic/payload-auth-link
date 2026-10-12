import { describe, expect, it } from 'vitest'
import {
  createBetterAuthCollections,
  createBetterAuthEngine,
  createBetterAuthProvider,
  createPayloadDatabaseAdapter,
  getBetterAuthSessionCookieNames,
  translateWhereClause,
} from '../index.js'

describe('provider-better-auth entrypoint', () => {
  it('exposes the adapter surface', () => {
    for (const entry of [
      createBetterAuthCollections,
      createBetterAuthEngine,
      createBetterAuthProvider,
      createPayloadDatabaseAdapter,
      getBetterAuthSessionCookieNames,
      translateWhereClause,
    ]) {
      expect(typeof entry).toBe('function')
    }
  })
})
