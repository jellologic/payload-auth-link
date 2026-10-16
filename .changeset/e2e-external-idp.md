---
---

Examples and e2e only (issue #84): an `E2E_MOCK_IDP` variant of both examples wires social OAuth, Google One Tap, phone sign-in, SSO domain enforcement, multi-session, `roleValues`, and `reqUser: 'document'` against a local mock OIDC provider, with Playwright specs (`bun run e2e:idp`, `bun run e2e:tanstack-idp`) and two CI jobs. No published package changes.
