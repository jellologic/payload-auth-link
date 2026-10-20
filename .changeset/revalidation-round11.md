---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/migrate': minor
---

The 0.17.0 re-validation batch: engine-boundary account-state enforcement, admin logout ends the provider session, adopted-role bridging, and scoped plugin writes.

- **provider-better-auth** (GHSA-62xf-qq8f-x6w9, GHSA-xxff-hh6q-c99p): a new engine plugin enforces the account state at the Better Auth boundary — an ACTIVE admin ban (`banned` + `banExpires`) or a CAP-7 suspension refuses `get-session`, every authenticated provider endpoint, and fresh sign-ins, and the port refuses session resolution, server-side mints, and API-key verification for such users. Before this, both states were enforced only where payload-auth-link resolves a session: banned users kept live sessions and working API keys, and suspended users could sign in fresh and act through every Better Auth endpoint. The user row is read FRESH per request via the internal adapter, so a ban or suspension applies to the next request without revocation. `suspendedUntilField` (engine input) names the CAP-7 field for renamed hosts.
- **plugin** (GHSA-gw3c-8g59-q72j): the users collection gains an `afterLogout` hook — admin Log out now revokes the presented provider session server-side and expires the provider's session/logout/multi-session cookies; Payload-local-only logouts are untouched.
- **provider-better-auth** (issue #143): adopted hasMany role fields bridge to Better Auth's string form — comma-joined on read (so `/admin/*` endpoints stop 500ing and `get-session`'s `user.role` is a string), split back to the array on write (`set-role`, `create-user`).
- **plugin/core** (issue #144): the JIT identity link/unlink writes only the plugin-owned fields through the adapter (a legacy row failing unrelated required validation no longer blocks sign-in), and every plugin-initiated Local API write carries `context[authLinkWriteMarker] = { op }` (exported from core) so host hooks can skip them. Link/unlink no longer bump `updatedAt`, create version rows, or run host hooks.
- **migrate** (issues #142, #145): the doctor warns on payload-auth's JSON-encoded legacy invitation roles (`["member"]`) and on adopted provider collections whose credential fields (password hashes, OAuth tokens, session tokens, API keys) are readable by non-managers. `docs/migrating-from-payload-auth.md` covers both.
