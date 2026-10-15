---
'@payload-auth-link/plugin': minor
---

Provider-backed admin login view (issue #55):
`authLink({ admin: { loginView: 'provider' } })` swaps Payload's local
login view for one that runs admin sign-in through the configured
provider (email+password, magic link, social — whatever the provider
exposes) plus the break-glass local fallback form for UNLINKED
operator accounts (0.7.0 refuses provider-linked documents on the
local login path by design). The view is a Payload custom view;
the import map must include
`@payload-auth-link/plugin/admin#ProviderLoginView` (the doctor
counts it). `Upgrade impact:` none — opt-in; the default stays
Payload's local login.
