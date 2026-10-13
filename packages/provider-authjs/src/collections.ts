import { assertUniqueSlugs, denyAllAccess, resolveSlugs } from '@payload-auth-link/core'
import type { CollectionConfig, Field } from 'payload'

/** Access control for the Auth.js system collections. */
export type AuthJsCollectionsAccess = NonNullable<CollectionConfig['access']>

/** Canonical Auth.js models persisted in Payload. */
export type AuthJsModelKey = 'user' | 'account' | 'session' | 'verificationToken' | 'authenticator'

/** Payload collection slugs backing each Auth.js model. */
export type AuthJsCollectionSlugs = Record<AuthJsModelKey, string>

/** Default `aj-*` slugs; override per model via options. */
export const defaultAuthJsSlugs: AuthJsCollectionSlugs = {
  user: 'aj-users',
  account: 'aj-accounts',
  session: 'aj-sessions',
  verificationToken: 'aj-verification-tokens',
  authenticator: 'aj-authenticators',
}

/** Slug overrides and access for {@link createAuthJsCollections}. */
export type AuthJsCollectionsOptions = {
  /** Override any default slug. Unmentioned models keep their defaults. */
  readonly slugs?: Partial<AuthJsCollectionSlugs> | undefined
  /**
   * Access control for the system collections. Defaults to deny-all: these
   * hold sessions and token material, so only the adapter (which uses
   * `overrideAccess`) touches them. Builders may loosen `read` for
   * operations debugging.
   */
  readonly access?: AuthJsCollectionsAccess | undefined
}

/**
 * Payload collections backing the Auth.js adapter. Field names mirror the
 * Auth.js models 1:1 with these exceptions: the user id lives in `auId`
 * (Payload owns the document `id`); accounts and verification tokens carry
 * a composite `key` (unique) because Payload has no compound unique
 * indexes — for verification tokens that gives `(identifier, token)`
 * uniqueness, so the same token hash (e.g. two identical 6-digit email
 * OTP codes) can coexist for different identifiers while a repeated pair
 * is rejected. The users collection additionally holds `passwordHash` for
 * the credentials service — Auth.js itself never reads it.
 */
export function createAuthJsCollections(options?: AuthJsCollectionsOptions): CollectionConfig[] {
  const slugs: AuthJsCollectionSlugs = resolveSlugs(defaultAuthJsSlugs, options?.slugs)
  assertUniqueSlugs(slugs, 'Auth.js collections')
  const access: AuthJsCollectionsAccess = options?.access ?? denyAllAccess()
  const hidden = { admin: { hidden: true }, access } as const

  const userFields: Field[] = [
    { name: 'auId', type: 'text', required: true, unique: true },
    { name: 'email', type: 'email', required: true },
    { name: 'name', type: 'text' },
    { name: 'image', type: 'text' },
    { name: 'passwordHash', type: 'text' },
    { name: 'emailVerified', type: 'date' },
  ]
  const accountFields: Field[] = [
    { name: 'key', type: 'text', required: true, unique: true },
    { name: 'provider', type: 'text', required: true },
    { name: 'providerAccountId', type: 'text', required: true },
    { name: 'userId', type: 'text', required: true },
    { name: 'type', type: 'text', required: true },
    { name: 'access_token', type: 'text' },
    { name: 'refresh_token', type: 'text' },
    { name: 'id_token', type: 'text' },
    { name: 'token_type', type: 'text' },
    { name: 'scope', type: 'text' },
    { name: 'expires_at', type: 'number' },
    { name: 'session_state', type: 'text' },
  ]
  const sessionFields: Field[] = [
    { name: 'sessionToken', type: 'text', required: true, unique: true },
    { name: 'userId', type: 'text', required: true },
    { name: 'expires', type: 'date', required: true },
  ]
  const verificationTokenFields: Field[] = [
    // Not `required` (upgrade safety, B2/B6): this column was added in
    // 0.2.0, and a NOT NULL addition breaks every pre-0.2.0 database —
    // SQLite push recreates the table (losing rows), Postgres
    // migrations fail on existing NULLs. Unique indexes tolerate
    // NULLs on SQLite/Postgres, the adapter always writes `key` on
    // create, and the read path (`useVerificationToken`) finds rows
    // by `(identifier, token)`, so pre-0.2.0 rows with a NULL key
    // keep working until they are consumed. Never re-add `required`
    // without a backfill migration.
    { name: 'key', type: 'text', unique: true },
    { name: 'identifier', type: 'text', required: true },
    { name: 'token', type: 'text', required: true },
    { name: 'expires', type: 'date', required: true },
  ]
  const authenticatorFields: Field[] = [
    { name: 'credentialID', type: 'text', required: true, unique: true },
    { name: 'userId', type: 'text', required: true },
    { name: 'providerAccountId', type: 'text', required: true },
    { name: 'credentialPublicKey', type: 'text', required: true },
    { name: 'counter', type: 'number', required: true },
    { name: 'credentialBackedUp', type: 'checkbox', required: true },
    { name: 'credentialDeviceType', type: 'text', required: true },
    { name: 'transports', type: 'text' },
  ]

  return [
    { slug: slugs.user, ...hidden, fields: userFields },
    { slug: slugs.account, ...hidden, fields: accountFields },
    { slug: slugs.session, ...hidden, fields: sessionFields },
    { slug: slugs.verificationToken, ...hidden, fields: verificationTokenFields },
    { slug: slugs.authenticator, ...hidden, fields: authenticatorFields },
  ]
}
