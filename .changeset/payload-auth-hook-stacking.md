---
'@payload-auth-link/migrate': patch
---

The migration doctor now warns (`payload-auth-hook-stacking`) when a SOURCE config runs payload-auth ≤ 1.9.x on better-auth ≥ 1.6 (#156): payload-auth rewrites the app's own `betterAuthOptions.hooks` object in place on every config build, so a second build in the same process — an HMR reload, a config module that failed once and was re-evaluated, a test building the config twice — stacks the wrappers and breaks every Better Auth endpoint (every admin request signed out, `getSession` answering a `{headers,response}` envelope, `better-auth-strategy` throwing on `res.session.userId`). The guide's payload-auth section documents the failure, its fingerprint, and the interim workaround; a regression test in provider-better-auth pins that payload-auth-link never does this — two engine builds from one options object leave every endpoint working and the app's hooks object untouched.
