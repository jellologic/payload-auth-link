---
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

Fix the GHSA-xxff endpoint-boundary suspension check (GHSA-jvpf-3fhq-f5ph): the account-state middleware read the user row via Better Auth's internal adapter, which returns only BA-schema fields — the CAP-7 `suspendedUntil` column is not declared there, so the boundary check never saw a suspension on an existing session (bans were fine; the admin plugin declares those fields). The engine now wires a Payload-backed row reader into the middleware — honoring `schemaMap.user`, `idStrategy`, and `suspendedUntilField` — the same reader the mint/verify refusals use. Regression: adopt mode, suspension set through the raw adapter (hooks bypassed, live session not revoked): `get-session` 403, `update-user` 403, Payload-side session endpoint 401.
