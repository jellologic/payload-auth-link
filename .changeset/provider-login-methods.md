---
'@payload-auth-link/core': patch
'@payload-auth-link/plugin': patch
'@payload-auth-link/provider-better-auth': patch
---

`ProviderLoginView` (the `loginView: 'provider'` admin login screen) gains native alternative sign-in methods (#157): a "Continue with …" button per social provider the engine actually configured, and — with Better Auth's magic-link plugin installed — an email form posting Better Auth's own `sign-in/magic-link` endpoint with a "check your email" state. Passwordless adopt-mode apps (local strategy disabled, magic-link/social users — the payload-auth 1.9.4 shape) sign their users in at `/admin/login` without an app-side custom view. The methods are derived from the provider port, never configured separately: `IdentityProviderPort` grows optional `socialProviders` (the configured ids) and `magicLinkEnabled` facts, the better-auth engine derives both from the instance's options and plugin list, and the plugin forwards them into the view. Without the facts the view renders exactly as before.
