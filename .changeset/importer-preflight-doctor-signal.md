---
'@payload-auth-link/migrate': patch
---

The importer fails fast on the wrong config, and the doctor's signal is clean (issue #75, from the real-data re-verification).

- **The importer refuses configs that declare no payload-auth-link target collections BEFORE booting** — an untouched payload-auth app's config has no `ba-*` collections to write to, and the failed run used to park forever on the boot's live database pool (0% CPU, no output, never exits). It now refuses at the config-module read with the fix in the message, the Payload boot runs under a 120s watchdog, and a failed CLI exits the process outright. The guide states plainly that the importer runs against the TARGET config.
- **Doctor plugin detection requires a Better Auth import and skips test files**: a security-tail test mentioning `mcp(` no longer blocks the doctor (the app used Payload's own MCP plugin), and `admin(` in prose or another package's API is noise, not a plugin. The unverified-users warning now matches the imported-identity semantics (#69): imported unverified users are pre-linked and resolve on their next sign-in after verifying — no operator action required.
- **Node parity**: vitest inlines the CSS-bearing `@payloadcms/ui` chain and stubs CSS (an externalized `react-image-crop` stylesheet crashed some Node runtimes with `Unknown file extension ".css"`), and CI adds a Node 20/22/24 matrix running the suite under each runtime.

Upgrade impact: none stored — the pre-flight runs before any database access; CLI behavior on an untouched config changes from an indefinite hang to a fast named failure with exit 1.
