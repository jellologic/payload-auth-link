---
'@payload-auth-link/migrate': minor
---

Re-validation follow-ups (issue #119): the doctor closes its last blind spot, and two refusals read straight.

- **The doctor blocks on a missing `payload_kv` table** (`payload-kv-table-missing`): a production database whose app never ran the Payload migration creating Payload's key-value store passed every other check and surfaced only as an `--apply`-time refusal. When the config under inspection installs payload-auth-link (the database `--apply` writes to) and the table is absent, the doctor now names it up front, with the fix (`payload migrate`).
- **Rollback refusals name the flag's source**: a manifest marked `finalized` is refused with "the manifest is marked finalized (the finalize command writes that flag into the manifest file)" instead of the ambiguous "the migration is finalized" — the refusal was always correct, but an operator who never ran finalize could not tell where the mark came from.
- `finalize failed:` gained its missing space, matching every other command's error prefix.
