---
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/plugin': minor
---

Coexistence window (issue #51): `createBetterAuthEngine({ legacySessions: { until, cookieNames } })`
honors legacy payload-auth session cookie names READ-ONLY until the
ISO `until` date — the lookup re-presents them under the current
names (suffix-preserving, so `.sig` signatures ride along when the
app keeps the same `BETTER_AUTH_SECRET`), while minting always uses
the current names. After the window the legacy names are refused with
a session miss. The engine exposes `legacySessionCookieNames` for
cookie helpers and Edge middleware; the plugin mirrors the
declaration (`legacySessions`) for the doctor's expiry check.
`Upgrade impact:` none — additive, opt-in.
