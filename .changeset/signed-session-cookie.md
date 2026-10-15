---
'@payload-auth-link/core': minor
'@payload-auth-link/provider-better-auth': minor
'@payload-auth-link/plugin': minor
---

The server-session API's cookie is actually signed, and the server API is stricter about providers (issues #68–#72 correctness pass, found in the first production rehearsal).

- **`sessionCookie(token)` now returns `Promise<string>`** on `authLinkServer(payload)` and the provider port, and emits Better Auth's SIGNED form (`token.<HMAC>` — BA reads the session cookie with `getSignedCookie` only, so 0.9.0's raw-token cookie resolved no session). The cookie is built from the engine's own resolved context: secret, cookie name, and the real `Secure`/`SameSite`/`Path`/`Max-Age` attributes. `createSessionFor().setCookie` carries the signed value; await the call.
- **`revokeAllForUser` and `listSessions` walk every linked provider**, not just the first capable identity — with two linked providers, the second provider's sessions were neither listed nor revoked.
- **`sessionCookie(token)` refuses ambiguity**: with several cookie-transport providers registered it throws instead of silently signing with the wrong one (`createSessionFor` remains the unambiguous path).
- **`legacySessions` on the plugin now enforces agreement** with the engine's window at config time (`InvalidConfigError` on missing, disagreeing, or colliding windows; engine-only configuration stays legal — the engine input is what acts).
- **`admin: { loginView: 'provider' }` renders**: the registration gains its `exportName` and the view signs in through Better Auth's `POST /sign-in/email` (the old `/api/auth/sign-in` link was never a route), with a two-factor-aware response and a path for social-only accounts. Requires a cookie-transport provider (config-time error otherwise), and **apps enabling it must regenerate the Payload import map** (`payload generate:importmap`).

Upgrade impact: type-level — `await sessionCookie(…)` at call sites; behavior-level — hosts that set only the plugin's `legacySessions` option must move the window to the engine input (the plugin option now asserts it); hosts using `loginView: 'provider'` regenerate the import map. No collection shapes change; no stored data is touched.
