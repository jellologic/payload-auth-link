---
---

Examples and e2e only (issue #84): a Better-Auth-only `E2E_MFA_POLICY=1` variant of `examples/basic` wires `policies.requireMfaForRoles`, with a Playwright spec (`bun run e2e:mfa`) and a CI job. No published package changes.
