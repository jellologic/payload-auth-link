---
'@payload-auth-link/core': patch
'@payload-auth-link/web': patch
'@payload-auth-link/react': patch
'@payload-auth-link/plugin': patch
'@payload-auth-link/next': patch
'@payload-auth-link/tanstack-start': patch
'@payload-auth-link/provider-better-auth': patch
'@payload-auth-link/provider-authjs': patch
---

Packaging fixes found by verifying 0.1.0 from a clean consumer install:

- next: `dist` imported `next/headers`, `next/navigation` and
  `next/server` without `.js`, so the adapter crashed under plain
  Node ESM (`ERR_MODULE_NOT_FOUND`). The imports now carry `.js`, and
  lint enforces it.
- plugin: `@payload-auth-link/plugin/admin` imports `@payloadcms/ui`
  but never declared it. It is now an optional peer dependency (only
  the `/admin` subpath needs it, and Payload apps already have it).
- all: compiled tests (`dist/**/__tests__`) no longer ship in the
  tarballs (0.1.0 `core` carried 56 test files).
- all: every package now ships a README, so its npm page explains the
  package, install line with peers, exports, and guides instead of
  "No README data found!".

This is the first release CI publishes through npm trusted publishing,
with provenance.
