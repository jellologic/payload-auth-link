# Capabilities guide

How to wire every sign-in capability beyond email/password, per the
[capability plan](PLAN-CAPABILITIES.md). One rule governs all of it:
providers authenticate and report facts; core decides uniformly;
Payload owns the users. A capability is usable only when the
provider **declares** it — wiring a feature on an undeclared
capability throws `UnsupportedCapabilityError` at composition time,
never silently at runtime.

Capability declarations are derived, never asserted:

- **Better Auth**: from the plugin list you actually install
  (`admin` → `impersonation`, `magic-link` → `magic-link`,
  `email-otp` → `email-otp`, `generic-oauth` or configured social
  providers → `oauth`, `one-tap` → `one-tap`, `passkey` → `passkey`,
  `two-factor` → `mfa`, `phone-number` → `phone`, `anonymous` →
  `anonymous`, plus `revoke-user-sessions` always). See
  `betterAuthCapabilities` in `@payload-auth-link/provider-better-auth`.
- **Auth.js**: from the providers you configure (`email` →
  `magic-link`, `oauth`/`oidc` → `oauth`, database session strategy
  → `revoke-user-sessions`). Auth.js has no MFA, phone, anonymous,
  impersonation, or production passkey primitive — policies needing
  them fail at wiring on Auth.js (by design; that is the honest
  answer, not an error to work around).

## Support matrix

The canonical capability-by-provider matrix lives in
[Compatibility](compatibility.md#sign-in-capabilities-by-provider) —
this guide covers how to wire each row.

## Passwordless (CAP-1, CAP-2)

**Better Auth:** install `magicLink({ sendMagicLink })` and/or
`emailOTP({ sendVerificationOTP })`. Both verify the email, so the
sessions link and provision through the normal verified-email gate.
Plugin-owned user fields need no declarations for these two.

**Auth.js:** add an Email provider (magic link). For 6-digit codes
use the recipe helpers from `@payload-auth-link/provider-authjs`:

```ts
Resend({
  maxAge: emailOtpMaxAgeSeconds, // 300, not the 24h default
  generateVerificationToken: emailOtpVerificationToken,
  sendVerificationRequest,
})
```

The email callback reads `token`/`email` from the **query string
only** — build code-entry URLs with `buildEmailOtpCallbackUrl`, not
a POST body. Examples capture mail in a dev mailbox
(`examples/*/lib/dev-mailbox.ts`); production sends real email.

**Abuse control (CAP-18).** Better Auth counts OTP guesses per
identifier natively (`allowedAttempts`, default 3 — past the cap the
genuine code is dead too). Auth.js does **not** count wrong codes,
so there the cap is yours: the examples throttle the email callback
per email+IP (`429` past 3 attempts in 10 minutes, in each
example's Auth.js route handler). Layer per-IP send/verify limits on
top in both cases. A limiter keyed on a forwarded-IP header is only
as trustworthy as your proxy config — spoofed `X-Forwarded-For`
values from untrusted clients must never mint fresh buckets.

## OAuth / OIDC (CAP-3)

**Better Auth:** core social providers or `genericOAuth`. BA sets
`emailVerified` from the IdP profile, and the plugin refuses
unverified assertions (401, no provisioning).

**Auth.js:** Auth.js creates every OAuth user with
`emailVerified: null`. To let specific IdPs' assertions through,
allow-list them explicitly (decision D6):

```ts
createAuthJsEngine({
  trustProviderEmailVerification: ['google', 'acme-oidc'],
  // ...
})
```

Only an asserted `email_verified: true` for the user's own email
stamps. This is incompatible with that provider's
`allowDangerousEmailAccountLinking` (wiring throws). Integration
tests run both providers against a local mock IdP
(`__tests__/oauth.test.ts` in each adapter) — no hosted IdP needed.

## Google One Tap (CAP-4)

**Better Auth:** install the `oneTap` plugin.
**Auth.js (recipe):** a Credentials provider whose `authorize` is
`createGoogleOneTapAuthorize({ clientId, upsertUser })` from
`@payload-auth-link/provider-authjs`. The helper verifies the ID
token locally against Google's JWKS (signature, issuer, audience,
expiry) and only resolves verified-email profiles; you own
persistence in `upsertUser`. `verifyGoogleIdToken` is exported for
non-Credentials shapes. One Tap goes stale fast — pin it behind
your own kill switch.

## Passkeys (CAP-5)

**Better Auth:** install `@better-auth/passkey` and declare its
model for the Payload adapter:

```ts
createBetterAuthEngine({
  customModels: [
    {
      model: 'passkey',
      fields: [
        { name: 'name', type: 'text' },
        { name: 'publicKey', type: 'text', required: true },
        { name: 'userId', type: 'text', required: true },
        { name: 'credentialID', type: 'text', required: true },
        { name: 'counter', type: 'number', required: true },
        { name: 'deviceType', type: 'text', required: true },
        { name: 'backedUp', type: 'boolean', required: true },
        { name: 'transports', type: 'text' },
        { name: 'aaguid', type: 'text' },
      ],
    },
  ],
  options: { plugins: [passkey({ rpID, rpName, origin })] },
})
```

Register/manage from the account area, sign in from `authClient.signIn.passkey()`.
Better Auth does not mark which ceremony created a session, so
`assurance.methods` stays `'unknown'` — passkey sign-in neither
claims nor denies `'passkey'` as a method.

**Auth.js:** WebAuthn is experimental upstream; this adapter ships
the `aj-authenticators` collection groundwork only and declares no
passkey capability.

## Two-factor and MFA policy (CAP-6)

**Better Auth:** install `twoFactor()` (+ `twoFactorEnabled` custom
field and the `twoFactor` custom model, as in the examples). BA
marks no per-session TOTP proof, so mapped `assurance.mfa` means
**enrolled** (`twoFactorEnabled`) — an enrollment gate, not recency
proof.

Enforce with either or both:

```ts
// Plugin: withhold roles from sessions without MFA proof.
// Throws at wiring unless every provider declares 'mfa'.
authLink({ policies: { requireMfaForRoles: ['admin'] } })

// Route level (web/next/tanstack-start): typed step-up error.
await requireRoles(headers, verifySession, { roles: ['admin'], requireMfa: true })
```

The plugin projects withheld roles out of the session user and sets
`mfaRequired: true` so UIs prompt for step-up instead of a flat 403.
`denyWithoutMfa()` in `@payload-auth-link/plugin` guards sensitive
collections the same fail-closed way as `denyWhileImpersonating`.

## Suspend and revoke (CAP-7)

Set `suspendedUntil` (and optionally `suspendReason`) on the Payload
user. Session verification refuses that user for **every** provider
and strategy — including stateless JWTs no provider can revoke —
until the instant passes or the field is cleared. As defense in
depth, providers declaring `revoke-user-sessions` (Better Auth
always; Auth.js on the database strategy) also drop the provider
sessions. `suspendReason` is operator-facing and never sent to
clients. Suspension writes are denied while impersonating and are
limited to the role-manager roles (`roleManagerRoles`, default
`['admin']`); reads of the suspension fields are role-manager only.

## Phone sign-in (CAP-9)

Payload users carry a verified E.164 `phone` field. Verified phone
claims sync onto the linked user automatically; to let phone-only
identities link to the **existing** user holding that number, opt in:

```ts
authLink({ linkingPolicy: { kind: 'verified-email-or-phone' } })
```

A verified phone never provisions a new Payload user (verified-email
registration stays the only provisioning path), never links an
unverified claim, and never steals a number another user holds.
Every provider must declare `'phone'` or wiring throws.

## Guests (CAP-10)

With Better Auth's `anonymous` plugin, an anonymous session is a
**guest**: the session endpoint answers
`{ user: null, guest: { id, providerId, expiresAt } }`, React
exposes `guest` beside `user`, and no Payload user, roles, or access
come with it. Key anonymous state (carts, drafts) on `guest.id`;
when the guest later signs in for real, migrate that state in your
sign-in completion handler. Guest documents are never created in
Payload — that is the point.

## Organizations (CAP-11)

Payload-owned and provider-independent (decision D1):

```ts
authLink({ organizations: { enabled: true } })
```

This adds `organizations` + `memberships` collections (reads scoped
to members, writes to managers) and endpoints for list/create/
invite/accept under `/api/auth-link/organizations*`. Invite by
email: existing users join immediately, unknown addresses wait as
`invited` until that user accepts; duplicates get `409`. Delivering
the invitation itself (email, in-app notice) is your app's job — the
plugin owns the record and the acceptance check, not a mailer.
Authorization reads live membership data via
`requireOrgRole(req, { organizationsCollection, membershipsCollection, orgRoles, ssoProviders }, { organizationId, roles })`
— pass the same slugs/roles you gave `authLink`. There is
deliberately **no** active-organization session state: your app
carries the org selection and asks per request.

Membership governance holds on every channel (REST, GraphQL, admin,
the plugin's endpoints, and trusted Local-API writes where noted):

- A membership's `organization` and `user` are **immutable** after
  create — field access drops REST writes, and a `beforeChange`
  guard throws for any other writer (Local API with
  `overrideAccess` included). The only sanctioned `user` write is
  the plugin's own invite acceptance.
- Role writes (membership create/update/delete, invites) require a
  manager of that organization and **never exceed the caller's own
  role**: `orgRoles` order is the rank, so an `admin` cannot mint or
  promote an owner, nor edit or remove an owner's membership.
- An organization **always keeps an active owner**: demoting or
  removing the last one is refused with `409` (Local API included).
  Promote a second owner first. The guard also holds when two owners
  remove each other at the same moment: each removal locks the
  organization row before counting owners (on transactional
  adapters), and re-counts after its write, restoring the row and
  answering `409` if no owner is left. Both racing requests may be
  refused; the organization is never left without an owner.
- Organization updates go to its managers (owner or `admin`);
  **deleting an organization is owner-only**, since it removes every
  membership, the owners' included. Bulk `PATCH`/`DELETE
/api/organizations?where=…` is scoped to the organizations the
  caller manages (or owns, for delete); a value in the request body
  never selects which organization authorizes the write.
- `DELETE /api/organizations/:id` **cascades**: the organization's
  memberships and pending invitations are deleted in the same
  request.
- Accepting an invitation after joining the organization another way
  answers `409` (`user is already a member`); the invitation stays
  pending for a manager to remove.
- While an operator **impersonates** a user, every organization
  write, membership write, invite, and acceptance is refused (`403`)
  and the attempt is audited (`onAudit` / logger, with `denied: true`
  and the endpoint path for plugin endpoints).

Provider-native org stores (e.g. BA `organization`) remain provider
features; they are never Payload authorization.

## Enterprise SSO (CAP-15)

Register the composition-root providers whose sessions are SSO
assertions, and keep each organization's `verifiedDomains` current.
Only Payload role managers (`roleManagerRoles`) can write
`verifiedDomains`, and never while impersonating; organization
owners and admins cannot, because a listed domain admits SSO
sign-ins for every address on it:

```ts
authLink({
  organizations: { enabled: true, ssoProviders: ['better-auth'] },
})
```

SSO sessions link **only** when the asserted email's domain exactly
matches a verified organization domain (no subdomain inheritance).
A tenant-registered IdP can assert verified emails for anyone —
the verified domain is the trust boundary that stops tenant A's IdP
minting sessions for tenant B. Non-SSO providers are unaffected.

The check is global, not per provider: a domain listed by **any**
organization admits sessions from **every** provider in
`ssoProviders`. The plugin has no mapping from an SSO provider to the
organization that registered it, so it cannot narrow this further.
Treat each domain you list as trusted for all registered SSO
providers, and verify domain ownership before adding it.

## Usernames and wallets (CAP-16, CAP-17)

BA's `username` plugin works for provider-side sign-in at the
identity layer — username changes propagate to Payload as CAP-14
identity events, but the Payload `username` stays builder-owned
data, never a second identity authority inside the plugin. SIWE
(CAP-17) mints placeholder-email identities
(`…@*.placeholder.invalid`): the adapter maps those to _no email
claim_, so a wallet is a guest at most until a verified email links
it — the same rule covers anonymous placeholder addresses.

## API keys (`@better-auth/api-key`)

API keys work when the satellite's model is declared — verified end
to end (issue #16), probed by the committed schema probe. Declare the
`apikey` model in `customModels` (the field list mirrors BA's
`getAuthTables` output, minus Payload-owned `createdAt`/`updatedAt`;
or let `autoDeclare: true` derive them for you — the recipe below), compose the plugin, opt keys into
sessions, and admit the channel:

```ts
import { apiKey } from '@better-auth/api-key'

// engine options
plugins: [
  apiKey({ defaultPrefix: 'bock_', enableSessionForAPIKeys: true }),
  // ...
],
customModels: [
  { model: 'apikey', fields: [/* getAuthTables output, minus createdAt/updatedAt */] },
],

// plugin options
authLink({ /* ... */ admitChannels: ['cookie', 'api-key'] })
```

Clients then present `x-api-key: <key>`; the request verifies through
the `auth-link` strategy, so Payload REST sees the user. **Security
posture:** a key session carries its owner's Payload roles, so an
admin's key IS an admin credential — issue keys to humans sparingly,
scope them with BA's `metadata`/`permissions` plus your own access
functions, and expire them. MFA policy: key sessions report
`assurance.mfa: false`, so any role gated by `requireMfaForRoles`
stays withheld from API keys — fail-closed by design. Without
`enableSessionForAPIKeys` and the admitted channel, a key
authenticates nothing (D8).

## Deriving declarations from Better Auth's schema (issue #17)

Hand-declaring `customFields`/`customModels` for every plugin is
reviewed-in-code strictness; when you compose many plugins, derive
them instead:

```ts
createBetterAuthEngine({
  autoDeclare: true, // derive from getAuthTables(options)
  options: { plugins: [organization(), admin(), apiKey({/* ... */})] },
})

// or compute them yourself:
import { deriveBetterAuthSchema } from '@payload-auth-link/provider-better-auth'
const { customFields, customModels } = deriveBetterAuthSchema(options)
```

Semantics: arrays and unknown BA types map to a JSON column;
enum-valued attributes stay text (BA owns value validation); a BA
`defaultValue` makes the column nullable (BA writes before applying
defaults); renames (`modelName`/`fieldName`) throw — declare those by
hand, the adapter serves canonical names. `autoDeclare` merges under
your explicit declarations, so a hand-pinned field always wins. Keep
the drift alarm: pin the derived output in a snapshot test —

```ts
const derived = deriveBetterAuthSchema(options)
expect(derived).toMatchSnapshot() // a BA bump that changes the schema fails here
```

## Sessions across channels (CAP-13)

`admitChannels` (default `['cookie']`) is the deployment's explicit
list of admitted session presentations, checked after session
validation — server-only configuration; nothing on the wire can
widen it. Bearer admission also skips the plugin endpoints' origin
check for bearer-presented requests (Bearer tokens are not ambient
credentials; CSRF does not apply to them). With BA `multiSession`,
plugin logout revokes **every** presented device session and
expires every presented multi cookie. API-key and device-code
sessions verify through their provider, but the observed channel is
fail-closed: an api-key presentation is only admitted when you list
`'api-key'`.

Known issue: with `'bearer'` admitted, Payload's `GET /api/users/me`
answers 500 for a Better Auth bearer session (Payload decodes the
`Authorization: Bearer` value as a JWT, and BA's token is opaque).
Use `GET /api/auth-link/session` for bearer clients; every other
route works on the same token. Pinned as `it.fails` in
`channel-bearer-engine.test.ts`.
