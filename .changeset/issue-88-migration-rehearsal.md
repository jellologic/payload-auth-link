---
'@payload-auth-link/migrate': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/plugin': minor
---

Fixes from the real-data payload-auth → payload-auth-link rehearsal (issue #88).

**provider-better-auth** — `authLinkServer(payload).verifyApiKey` resolves valid `@better-auth/api-key` 1.7.x keys. The satellite names the owner `referenceId`; the port demanded `userId` and threw "key block is missing its user id" for every valid key. `referenceId` is read first, `userId` is the fallback.

**plugin** — a provider verification of the address a linked user ALREADY carries (the post-import verification) now grants the bound linking proof (`linkable` + `linkableEmail`); it used to change nothing. New `emailVerifiedField` option names a host checkbox (e.g. payload-auth's `emailVerified`) the plugin sets `true` on that verification; it must be a checkbox declared on the users collection (wiring throws otherwise).

**migrate**

- Every command prints and terminates: `from-payload-auth`, `verify`, `rollback`, and `finalize` log their outcome (`--json` prints one JSON document), and the booted Payload is destroyed with its Postgres pool closed — `@payloadcms/db-postgres` leaks a checked-out client that kept the CLI alive forever.
- Rollback is exact after any number of `--apply` passes: only the FIRST captured prior value per field is kept, `users.updated_at` is restored, and rollback resets the manifest so a re-apply starts fresh. Plan totals are per pass and no longer double.
- The manifest stores no email in the clear: prior values are sealed with AES-256-GCM under the app's `PAYLOAD_SECRET` (manifest version 2; version-1 manifests still roll back), and the file is written mode 0600.
- `verify` scopes the session check to imported rows: sessions created after cutover and expired imported sessions Better Auth cleaned up are reported, not failed.
- The importer carries Better Auth admin/anonymous state (`banned`, `banReason`, `banExpires`, `role`, `isAnonymous`) when the target declares those plugins, and refuses the run when a banned/anonymous user's state cannot be held. Row `createdAt`/`updatedAt` carry for accounts, sessions, verifications, API keys, jwks, orgs, members, and invitations.
- New `adopt-prelink` command (dry run by default, `--apply` + manifest, undone by `rollback --manifest`): one `better-auth` identity per adopted user plus the verified-email linking proof — the step adopt mode needed but did not ship.
- Doctor: no false `injected-field-collision` on a target config where the plugin is already installed; flags banned users, anonymous users (blockers when the target cannot hold them), `oauth_*` tables (not carried), and `genericOAuth` providers.

Upgrade impact: none on shipped collection shapes — no `ba-*` or plugin-injected users field changed (the bans/anonymous fields come from Better Auth's own plugins via `autoDeclare` when you declare them). Operators: run `rollback` with the same `PAYLOAD_SECRET` that ran `--apply`; delete the manifest after `finalize` and your soak window.
