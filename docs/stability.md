# Stability and upgrade policy

> **Status: this policy takes effect when a package reaches 1.0.0.**
> Until then the [pre-1.0 practice](#today-pre-10) below applies.
> The packages version independently (for example plugin 0.11,
> core 0.7, web 0.3), and each package moves to this policy at its
> own 1.0.

This page defines what counts as the public contract, what each
semver level may change, how things are deprecated and removed, how
security fixes ship, and what each release has to document.

## Today (pre-1.0)

This is the current practice, the same one stated under "Pre-1.0
policy" in [upgrading.md](upgrading.md#pre-10-policy):

- **A minor may break.** Option shapes, exported types and internal
  ports can change in a `0.x` minor. Every such change ships a
  changeset, a CHANGELOG entry, and (when you need to do something) a
  section in [upgrading.md](upgrading.md) named after the release
  versions.
- **A patch fixes bugs.** Most security fixes ship as patches (for
  example 0.10.1 with advisory GHSA-hxgq-9pww-59j4). When the fix has
  to tighten a default, it can ship in a minor (0.4.0's security
  default change).
- **The wire contract is already the anchor.** `SessionUser`, the
  endpoint paths and cookie behavior change only with a migration
  note, and new wire fields are additive and optional
  ([PORT-4](upgrading.md#session-wire-contract-gains-optional-facts-port-4)).
- **Schema changes are already gated.** The schema-change rules
  ([below](#collection-schemas)) apply today. CI enforces them with
  `bun run schema:check` and runs the golden-DB N/N−1 suite.
- **Exported types are already snapshotted.** `bun run api:check`
  fails when the built `.d.ts` surface drifts from
  `snapshots/api/<pkg>.txt`. Before 1.0, that forces a reviewed
  changeset. After 1.0, it forces the right semver level.
- **Only the latest `0.x` release gets security fixes**
  ([SECURITY.md](../SECURITY.md)).

## The public contract (from 1.0)

### 1. Wire contract

Anything a browser, a client bundle built against an older version,
or a separately deployed service can observe:

- **Routes** under Payload's API route:
  `GET`/`DELETE /auth-link/session`, and, when organizations are enabled,
  `GET`/`POST /auth-link/organizations`,
  `POST /auth-link/organizations/invite` and
  `POST /auth-link/organizations/accept`. Their methods, CSRF
  requirement (the `x-auth-link-csrf` header, exported as
  `csrfHeaderName`) and status codes are part of the contract.
- **Session endpoint bodies**: `200 { user: SessionUser }`,
  `200 { user: null, guest: { id, providerId, expiresAt } }` for an
  anonymous provider session, and `401`/`403` with `{ error }`;
  logout answers `200 { ok: true }`. The `SessionUser` shape is `id`,
  `collection`, `email` and `roles`, plus the optional `assurance`,
  `actor`, `organizationId` and `mfaRequired`. Adding an **optional**
  field is a minor change. Removing a field, renaming one, or making
  one required is a major change. Parsers (`parseSessionUser`) must
  keep ignoring unknown keys, so an older client can read a newer
  server.
- **Cookies.** The plugin mints no cookie of its own: session cookies
  belong to the provider. The contract covers which cookie names each
  adapter reads, re-presents and expires on logout (the
  `getBetterAuthSessionCookieNames` / `getAuthJsSessionCookieNames`
  helpers in the `/cookies` subpaths, including the `__Secure-` and
  `__Host-` prefix rules). If a change would sign users out or leave
  a cookie behind on logout, it is a major change.

### 2. Configuration

- `authLink(options)` (`AuthLinkPluginOptions`), the provider engine
  factories' options (`createBetterAuthEngine`, the Auth.js engine),
  and the adapter options (`createAuthMiddleware`,
  `createAuthRequestMiddleware`, `createSessionVerifier`, …).
- **Defaults are part of the contract.** Changing a default that
  loosens security, or that changes behavior for code that did not
  set the option, is a major change. The one exception is
  tightening a default to fix a vulnerability (see
  [Security fixes](#security-fixes)).

### 3. Exported API

- Every **package entry point** in a `package.json` `exports` map:
  `.` for every package, plus `@payload-auth-link/core/testing`,
  `@payload-auth-link/plugin/admin`,
  `@payload-auth-link/provider-better-auth/cookies` and
  `@payload-auth-link/provider-authjs/cookies`. Deep imports into
  `dist/` are not supported and not covered.
- **Core's public API is the explicit list in
  `packages/core/src/index.ts`.** That includes the port interfaces
  (`IdentityProviderPort`, `UserRepository`, `LoggerPort`, …) that
  third-party adapters implement. Adding a **required** member to a
  port is a major change. Adding an optional one is a minor change.
- **Typed errors** are contract by class (`instanceof`) and by the
  data they carry, not by message text.
- **`onAudit` events** are contract: the two messages
  (`impersonated operation`, `server session created`) and their
  field names ([audit.md](audit.md)). Audit consumers key on them.
- The API snapshot (`snapshots/api/`) is the mechanical check. A
  snapshot diff that removes or narrows anything needs a major
  changeset.
- **Not contract:** anything not reachable from an entry point;
  exports whose TSDoc says "Not public API" (for example
  `registerAuthLinkServer`); log message text and the fields of
  logger-only events; error message strings; the admin UI's markup;
  the example apps.

### 4. Collection schemas

The shapes Payload pushes or migrates are covered by the contract:
the provider collections (`ba-*`, `aj-*`), the organization
collections, and the fields the plugin injects into users. The
committed `snapshots/schema/*.json` is the mechanical check. These
are the rules from [AGENTS.md](../AGENTS.md), which apply before and
after 1.0:

- **Additive only by default.** A new column must be nullable or
  have a database default. Adding a column is a minor change, and
  the release notes must include migration steps.
- **No nullability, type or unique change, and no rename,** without
  a two-release expand → backfill → contract sequence. The previous
  minor must keep reading **and** writing the new schema. The golden-DB
  suite tests N against N−1.
- After 1.0, the **contract** step (dropping or narrowing what was
  expanded) is a major change.
- Every shape change ships a regenerated snapshot, a changeset with
  an `Upgrade impact:` section, an entry in `upgrading.md`, and a
  golden-DB upgrade test.

### 5. Supported bands

The runtime `supportedPayloadBand`, `supportedBetterAuthBand` and
`supportedAuthJsBand` constants equal the manifest peer ranges and
the CI compat matrix ([compatibility.md](compatibility.md)). They
always move together.

- **Widening** a band to an upstream version the matrix has proven
  is a patch or minor change.
- **Dropping** a supported upstream version, a database adapter or a
  Node major is a major change. The exception is an upstream that
  is itself end-of-life or has a vulnerability with no fix in that
  line. That exception ships with an advisory.

## Semver after 1.0

| Level | May contain                                                                                                                                                                                                        |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| major | any breaking change to the contract above; removal of anything deprecated in an earlier minor; schema contract steps; dropped bands                                                                                |
| minor | new options, exports, endpoints, optional wire fields, optional port members; additive schema (nullable/defaulted, with a migration); deprecations (with warnings); widened bands; security tightening (see below) |
| patch | bug fixes that restore documented behavior; security fixes that keep the contract; widened bands; docs                                                                                                             |

A fix that makes the code match its documentation is a patch, even if
someone depended on the bug. If the documentation was wrong instead,
the docs are corrected and the behavior stays.

## Deprecation policy

1. **Announce in a minor.** The deprecated API gets a TSDoc
   `@deprecated` tag that names the replacement, a CHANGELOG entry,
   and an `upgrading.md` entry. Where it can be detected at runtime,
   it also logs **one** warning through the configured logger (the
   pattern the payload-auth compat shim already follows).
2. **Keep it working for at least one minor.** The deprecated path
   behaves as before for at least one minor release after the one
   that deprecated it.
3. **Remove only in a major.** Removal ships in the next major after
   that window, and the `upgrading.md` section for that major lists
   every removal.

Time-boxed compatibility windows that are documented as dated (for
example `legacySessions` for payload-auth cookies) end on their
documented date. That is not a breaking change.

## Security fixes

- **Report privately** through GitHub security advisories
  ([SECURITY.md](../SECURITY.md)). Response targets are listed there.
- **Supported lines:** the latest minor of the current major.
  Proposed for 1.0: the last minor of the previous major also gets
  security patches for six months after a new major ships.
- **Delivery:** a patch release on each supported line, a published
  GitHub advisory (GHSA) with a CVE where one applies, and an
  `upgrading.md` entry when you need to do something.
- **Breaking for safety:** when the only safe fix changes the
  contract (tightening a default, refusing a credential path that
  used to work), the fix ships in a **minor** with the advisory and
  an `Upgrade impact` note that explains the opt-out, if one exists.
  It does not wait for the next major.

## Upgrade guide requirement

Every **minor** release, and any patch that needs operator action,
gets a section in [upgrading.md](upgrading.md):

- A heading that names the released version of every package that
  moved.
- What changed in behavior, what you have to do (configuration,
  migrations for each database adapter, cookie or session effects
  during a rolling deploy), and how to roll back
  ([N/N−1](upgrading.md#rolling-deploys-and-rollback-n-and-n1)).
- For schema changes, the `Upgrade impact:` section from the
  changeset (CI checks that it is there).

Every **major** additionally gets a single "x.y → (x+1).0" section
that lists every removal and every contract change.
