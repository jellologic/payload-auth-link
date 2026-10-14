---
'@payload-auth-link/migrate': minor
---

The runnable, reversible importer (issue #50):
`bunx @payload-auth-link/migrate from-payload-auth`.

Dry run by default (planned counts per model, unmappable rows,
unverified users); `--apply` copies users, credential accounts (hashes
verbatim), OAuth tokens, verifications, API keys, jwks and the
organization plugin's rows into the payload-auth-link collections,
granting `linkable`/`linkableEmail` from VERIFIED emails only and —
with the default `--sessions=carry` — carrying the session table so
nobody is logged out. Every created row and field change lands in the
manifest; `verify` checks both sides (non-zero exit on any mismatch),
`rollback` undoes exactly the manifest, `finalize` marks the point of
no return. Idempotent and resumable; the source tables are never
modified.

`Upgrade impact:` none — the CLI is additive and the source tables stay
untouched until you drop them yourself after `finalize`.
