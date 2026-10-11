# Mission

## Problem

`payload-auth/payload-auth` bolts Better Auth onto Payload CMS through
monkey-patches, stringly-typed schema maps, framework leaks, and `any`-heavy
plumbing. It fights Payload instead of extending it, so site builders inherit
its coupling, its silent fallbacks, and its upgrade risk.

## Mission

Build the enterprise-grade, strictly-typed, hexagonal replacement:
a Payload CMS v3 plugin that makes external identity providers
(Better Auth, Auth.js/NextAuth, WorkOS, Clerk) feel like first-class
Payload citizens — managed from Payload collections and the Payload admin —
while keeping every provider behind a swappable port.

## What "first-class Payload citizen" means

- Users live in a Payload collection. Roles, access control, hooks,
  validation, drafts, and versions behave exactly as in native Payload auth.
- Admins manage identities, linked accounts, and sessions from the
  Payload admin — no second dashboard, no out-of-band user store.
- The plugin follows Payload's plugin contract (`definePlugin`, strategies,
  endpoints, hooks, admin components, host-owned migrations) and never
  reaches around it.

## What "hexagonal" means here

- `core` owns the domain and the port interfaces; it imports no framework.
- Every external touchpoint — Payload storage, each identity provider,
  cookies/session transport, logging, tracing, transactions — is an adapter
  behind a port, registered explicitly at a composition root.
- Adding a provider means writing one adapter package, not touching the core.

## Provider roadmap

Initial build: Better Auth first, then Auth.js/NextAuth — the two
providers fully validatable with unit + e2e locally (self-hosted,
no SaaS dependency). Auth.js ships after its research spike.

Deferred post-v1: WorkOS and Clerk. Both are SaaS-backed and cannot
be fully validated locally; their ports stay reserved in the design
(`IdentityProviderPort` + registry keyed by id) but no adapter
packages ship in the initial build.

No provider ships without its adapter, its integration tests, and its e2e
coverage.

## Non-goals

- No fork of, or compatibility layer for, `payload-auth` internals.
- No second user store, shadow session table, or out-of-band auth cookie.
- No framework code in `core`; no Payload imports in UI packages;
  no React in the plugin outside `admin/`.
- No `any` at module boundaries; no silent fallbacks; no `console.*`.

## Quality bar

Strict TypeScript, `neverthrow`-style `Result` errors at boundaries,
Zod-validated inputs, lint-enforced package boundaries, and mandatory e2e:
every auth flow (sign-in, callback, webhook sync, logout, session revoke)
is proven against a real Payload app in Playwright before release.
