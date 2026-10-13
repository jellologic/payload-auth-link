---
'@payload-auth-link/provider-authjs': minor
---

Add the `trustProviderEmailVerification` engine option (D6): an allow-list of OAuth/OIDC provider ids whose asserted `email_verified === true` stamps the adapter user's `emailVerified` through `updateUser`, so trusted OAuth sign-ups can pass the plugin's verified-email gate. Nothing is stamped by default, for non-allow-listed providers, or when `email_verified` is false/absent, and combining a trusted provider with `allowDangerousEmailAccountLinking` now fails fast with `InvalidConfigError`. Also exports `createAuthLinkEvents` and `AuthLinkTrustOptions`.
