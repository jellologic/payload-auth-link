---
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

Fix the adopt identity-at-creation regression on Postgres (issue #135): 0.16.2's hook wrote its nested update without the request, so on Postgres it could not see the uncommitted row, threw NotFound, and rolled every adopt-mode sign-up back.

- The update now joins the create's transaction (`req`).
- A failed identity write is non-fatal: it logs, and the JIT link attaches the identity on the user's first resolution as before — a sign-up never fails for the identity row.
- The adopt sign-up + anonymous integration suite runs on Postgres in CI (`ADOPT_PG_URL`), where transaction isolation differs from SQLite in memory.
