import type { CollectionConfig, Config } from 'payload'

/**
 * The migration kit's own database-backed record store (issue #139).
 *
 * The kit records its database identity, its runs, and the finalize
 * marker through this collection — IN the database they describe, so a
 * restore, branch, or clone carries them and eviction can never drop
 * the finalize marker. It replaces the kit's former dependence on
 * `payload.kv` (issue #132): the app's key-value adapter is free to be
 * Redis or anything else — the kit no longer reads or writes it for
 * new records, and the kit-wide refusal is gone.
 *
 * Hidden and access-denied: the records are kit-internal, read and
 * written with `overrideAccess` by the migrate CLI through the Local
 * API. The slug is fixed (the kit resolves it structurally); a host
 * colliding with it fails config validation.
 */
export const migrationRecordsSlug = 'payload-auth-link-migrations'

export function migrationRecordsCollection(): CollectionConfig {
  return {
    slug: migrationRecordsSlug,
    labels: {
      singular: 'Migration Record',
      plural: 'Migration Records (payload-auth-link)',
    },
    admin: {
      hidden: true,
    },
    // The kit writes these records from a single CLI process — document
    // locking would join the app's payload_locked_documents tables with
    // a per-collection column those tables predate (issue #139's
    // reporter hit exactly that), failing every write on an existing
    // app. Nothing here needs concurrency protection.
    lockDocuments: false,
    access: {
      create: () => false,
      read: () => false,
      update: () => false,
      delete: () => false,
      readVersions: () => false,
    },
    fields: [
      {
        name: 'key',
        type: 'text',
        required: true,
        unique: true,
        index: true,
        admin: { description: 'The kit record key (payload-auth-link/migrate/…).' },
      },
      {
        name: 'data',
        type: 'json',
        required: true,
        admin: { description: 'The kit record payload (identity, run, or finalize marker).' },
      },
    ],
    timestamps: false,
  }
}

/**
 * Append the migration-records collection to the built config. A host
 * declaring the same slug collides: the kit resolves the store by this
 * fixed slug, so a rename would strand its records — fail the config
 * instead, with the remediation.
 */
export function withMigrationRecords(
  collections: Config['collections'],
  fail: (detail: string) => never
): Config['collections'] {
  const existing = (collections ?? []).find(
    (collection): collection is CollectionConfig => collection?.slug === migrationRecordsSlug
  )
  if (existing !== undefined) {
    fail(
      `the host already declares a '${migrationRecordsSlug}' collection: the migration kit records its database identity, runs, and finalize marker there (issue #139) — rename the host collection or point the kit at it deliberately`
    )
  }
  return [...(collections ?? []), migrationRecordsCollection()]
}
