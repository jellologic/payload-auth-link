---
'@payload-auth-link/provider-authjs': minor
---

Make Auth.js verification-token uniqueness composite on `(identifier, token)` instead of `token` alone: `aj-verification-tokens` gains a unique composite `key` field (the same pattern accounts already use) and `token` is no longer uniquely indexed by itself, so identical token hashes — for example two concurrent 6-digit email OTP codes for different addresses — can coexist, while creating the same `(identifier, token)` pair twice is rejected. `useVerificationToken` still looks up by identifier and token together and remains single-use, and rows written before the `key` field existed remain consumable. Hosts own the database migration for the new field, as with any collection change.
