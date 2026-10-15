---
'@payload-auth-link/migrate': minor
'@payload-auth-link/plugin': minor
---

Codemods + temporary `payload.betterAuth` compatibility shim (issue #53).

`bunx @payload-auth-link/migrate codemod --src ./src` rewrites the
named payload-auth call-site patterns (`getPayloadAuth()`,
`payload.betterAuth.api.getSession({ headers })`,
`toNextJsHandler(payload.betterAuth)`) and reports what needs a human
decision — nothing is half-rewritten. Dry run by default; `--write`
rewrites.

`createBetterAuthCompatShim(payload)` is the opt-in
`payload.betterAuth`-shaped accessor backed entirely by the supported
server API — same suspension gate, same MFA projection, same audit
sink, no back door — with one deprecation warning per process. The
doctor counts remaining shim call sites.
