---
'@payload-auth-link/provider-authjs': minor
---

`reconcileAuthJsMongoIndexes(payload)`: an idempotent one-time fix
for upgraded MongoDB deployments. Payload's mongo adapter never
drops indexes, so after the 0.1.1 → 0.2.x composite-token change
the stale `token` unique index kept enforcing the old one-row-per-
hash constraint, and the new `key` unique index built over rows
without the field. The helper backfills `key`
(`JSON.stringify([identifier, tokenHash])`), drops the stale
`token` index, and reports the `key` index state ('created' |
'present' | 'failed') without throwing while a build is in flight.
Covered by the env-gated Mongo golden test; run it once per
deployment after upgrading (see docs/upgrading.md).

Upgrade impact: MongoDB only. Already upgraded without it? The
composite-key behavior silently does not hold on your deployment
until you run the reconciliation. Fresh installs need nothing.
