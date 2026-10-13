---
'@payload-auth-link/core': minor
---

Add the provider conformance kit at the new test-only subpath export `@payload-auth-link/core/testing` (PORT-5): `assertProviderConformance` / `checkProviderConformance` take a port factory plus scenario drivers and assert session-shape narrowing and verified-claim semantics (including the deprecated `email`/`emailVerified` aliases matching the claim), declared capabilities matching behavior (`revokeUserSessions` exists iff `'revoke-user-sessions'` is declared, declared `'impersonation'`/`'mfa'` must be observable), actor propagation, channel reporting, and revoke semantics — with an explicit `best-effort` revoke mode for stateless JWT transports. It is framework- and test-framework-free, re-validates sessions at runtime, and both provider adapters now run it in their test suites. No runtime behavior changes.
