# Audit trail for production

What the plugin records about security-relevant events, where those
records go, and how to keep them somewhere that survives log
rotation. Everything here is read off the code: `audit.ts`,
`server.ts`, `session.ts`, `collections.ts`, `lifecycle.ts`,
`organizations.ts`, `repository.ts`, and core's use cases. The
recipe at the end is tested in
`packages/plugin/src/__tests__/audit-sink-recipe.test.ts`.

## Two channels: `logger` and `onAudit`

The plugin writes everything through one `LoggerPort`
(`authLink({ logger })`). The default is `consoleLogger()`, so
refusals and audit events show up with no configuration: `info` goes
to `console.info`, `warn`/`error` to the matching console level,
fields render as a JSON suffix, and `debug` is silent. To mute all
output, pass `nullLogger()`. In production, pass an adapter for your
real logger (pino, OpenTelemetry logs and so on). `LoggerPort` is
`debug`/`info`/`warn`/`error(message, fields?)` plus
`child(bindings)`.

`authLink({ onAudit })` is a separate **durable sink**. Its type is
`(event: { message: string; fields: LogFields }) => void`. The type
is reachable as `NonNullable<AuthLinkPluginOptions['onAudit']>`;
`AuditSink` itself is not exported from the package root. The plugin
wraps the logger with `composeAuditLogger(logger, onAudit)`. On every
`info` call the wrapper first calls `logger.info(message, fields)`,
then `onAudit({ message, fields: fields ?? {} })`. `warn`, `error`
and `debug` pass through to the logger and never reach the sink.

**Only two events reach `onAudit`.** The composed logger is used
only by the impersonation audit hooks, the organization endpoints'
impersonation refusals, and `authLinkServer(payload).createSessionFor`.
Every other event in this guide reaches the logger only. To keep
those durably as well, wrap the logger (see
[Recipe](#recipe-an-append-only-audit-log-collection)).

When a provider can impersonate (Better Auth's admin plugin), the
logger is silent (`nullLogger()`) and no `onAudit` is set, the plugin
prints one `console.warn` at `onInit` saying that impersonation audit
events will be dropped.

## Events delivered to `onAudit`

### `impersonated operation`

Payload's `beforeOperation` hook does the auditing. The plugin adds
it to **every collection and every global** in your config, its own
included, after all hooks you defined. It also fires from the plugin's
organization endpoints: when they refuse a request because the caller
is impersonating, and for the organization list
(`GET /auth-link/organizations`, allowed while impersonating). And it
fires for every users-document write that verifying an impersonated
session performs — writes no collection hook sees under the
impersonation: linking the target's provider identity to a document
or provisioning one (`operation: 'linkIdentity'`), and re-syncing an
already-linked target's email or phone from the provider
(`operation: 'setEmail'` / `'setPhone'`). Each write is recorded
once, by the request that performed it: concurrent first touches
that lose the provisioning race, and requests that find the target
already in sync, record nothing. It is emitted only while an
operator is impersonating the request's user. Plain requests return
before any logging.

Because the hook runs `beforeOperation`, attempts that are later
denied are audited too. For example, a role change that is blocked
while impersonating still produces an event.

| Field                 | When present                                              | Value                                                                                                                |
| --------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `actorKind`           | always                                                    | `'payload-user'`, `'provider-only'`, or `'malformed-actor'`                                                          |
| `actorProviderUserId` | actor parsed                                              | operator's provider user id                                                                                          |
| `actorUserId`         | `actorKind: 'payload-user'`                               | operator's Payload user id (string)                                                                                  |
| `targetUserId`        | `req.user` has an id                                      | impersonated user's Payload id (string)                                                                              |
| `operation`           | always                                                    | Payload's operation name (`read`, `update`, `delete`, …), endpoint verb, or `linkIdentity` / `setEmail` / `setPhone` |
| `collection`          | collection hook, verification write                       | collection slug                                                                                                      |
| `global`              | global hook                                               | global slug                                                                                                          |
| `endpoint`            | organization endpoint                                     | `/auth-link/organizations`, `/auth-link/organizations/invite`, `…/accept`                                            |
| `denied`              | organization endpoint refusal                             | `true` (the endpoint answered 403); absent on the allowed list read                                                  |
| `id`                  | the operation args name a document id; verification write | document id (string)                                                                                                 |

The fields carry ids only. Tokens, emails and document data are never
included. If the request carries an impersonation marker that cannot
be parsed, the plugin still audits it (fail-closed), with
`actorKind: 'malformed-actor'` and no made-up attribution.

**Outside the audit: Better Auth's own endpoints.** Requests an
impersonating operator sends straight to the provider — Better
Auth's `/api/auth/*` routes such as `/revoke-sessions`,
`/update-user` or `/list-sessions` — never pass through Payload's
operations or the plugin's endpoints, so the plugin records nothing
for them. Better Auth handles them as the impersonated user (an
`/update-user` that changes the name or image, a `/revoke-sessions`
that signs the user out everywhere). Audit them at the provider:
Better Auth's `hooks.after` / `databaseHooks` see the session's
`impersonatedBy`. An email change that comes back through
verification is the exception: it is the `setEmail` write above.

For the organization endpoints, `operation` is `read`
(`GET /auth-link/organizations`), `create`
(`POST /auth-link/organizations`), `invite`, or `accept`.
Organization governance refusals that do **not** involve
impersonation (not a manager, role above your own, invitation not
yours) return 403 and are not logged.

### `server session created`

Emitted by `authLinkServer(payload).createSessionFor(userId, options)`
after the provider has stored the session.

| Field        | Value                                                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| `providerId` | provider that minted the session                                                                        |
| `userId`     | Payload user id (string)                                                                                |
| `sessionId`  | opaque session handle (the session row id, never the bearer token)                                      |
| `reason`     | the caller's required `reason` string                                                                   |
| `actor`      | the caller's optional `actor` string, when given                                                        |
| `mfaProof`   | the caller's `mfaProof` boolean, when given                                                             |
| `expiresAt`  | ISO timestamp of the expiry the provider **stored** (or the requested one if the provider reports none) |

`reason` and `actor` are free text you supply, so keep personal data
out of them.

## Events that reach the logger only

These are emitted through the configured `logger`, not `onAudit`.
The list covers the security-relevant ones (diagnostics such as
storage failures are left out). Message text is diagnostic output,
**not** a stable contract (see [stability.md](stability.md)). If you
key durable capture on these strings, pin them in a test of your own.

| Level | Message                                                                                                                 | Fields                                                                                                               |
| ----- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| info  | `impersonated session used`                                                                                             | `providerId`, `actorProviderUserId`, `actorKind`, `actorUserId?`, `targetProviderUserId`, `targetUserId`             |
| warn  | `impersonated session actor has no linked Payload user`                                                                 | `providerId`, `actorProviderUserId`, `targetUserId`                                                                  |
| warn  | `session refused: user suspended`                                                                                       | `providerId`, `userId`, `suspendedUntil`                                                                             |
| warn  | `<scope> verification failed: user suspended` (scope: `strategy`, `session endpoint`, …)                                | `suspendedUntil`                                                                                                     |
| info  | `suspend: provider sessions revoked` (one per linked identity when `suspendedUntil` moves)                              | `providerId`                                                                                                         |
| error | `suspend: provider session revoke failed`                                                                               | `providerId`, `cause`                                                                                                |
| warn  | `provider session channel not admitted` / `<scope> verification failed: channel not admitted`                           | `providerId`, `channel`                                                                                              |
| warn  | `sso session refused: email domain not verified for any organization`                                                   | `providerId`                                                                                                         |
| warn  | `provisioning refused: the email is held by an existing document that is not proven to own it`                          | `providerId`, **`email`**                                                                                            |
| warn  | `email link refused: …` (pre-existing document not linkable, or proof bound to another email)                           | **`email`**, `userId`                                                                                                |
| warn  | `link refused: provider email unverified` / `registration refused: provider email unverified`                           | **`email`**, `providerId`                                                                                            |
| warn  | `link refused: anonymous identity never links`, `link refused: session carries no email identity claim`                 | `providerId`                                                                                                         |
| info  | `identity linked`, `identity linked by verified phone`, `user registered via provider`                                  | `userId`, `providerId`                                                                                               |
| info  | `local sessions revoked on identity link`                                                                               | `userId`, `providerId`                                                                                               |
| warn  | `identity linked to a document that also holds a local password; …`                                                     | `userId`, `providerId`                                                                                               |
| info  | `email synced from provider`, `phone synced from provider`                                                              | `userId`, `providerId`                                                                                               |
| info  | `verified email synced onto the linked user` (provider `email-verified` event)                                          | `userId`, `providerId`                                                                                               |
| info  | `email changed outside the provider resync; linking proof reset`                                                        | `userId`                                                                                                             |
| warn  | `identity event ignored: unverified email change (D9)`                                                                  | `providerId`, …                                                                                                      |
| warn  | `local password reset refused: document holds linked identities`                                                        | `userId`, `operation`                                                                                                |
| warn  | `local credential refused at authentication` (GHSA-mjvh: a dead account's Payload local JWT / API key resolves no user) | `userId`, `strategy` (`local-jwt` / `api-key`), `reason` (`suspended` / `provider-owned` / `provider-owned-api-key`) |
| warn  | `membership relocation refused`, `membership user rewrite refused`                                                      | `membershipId`                                                                                                       |
| warn  | boot: `payload-auth-link: N user doc(s) carry roles outside the configured set: …` (stored-role drift, B11)             | (counts in the message)                                                                                              |

The **bold** fields are emails. Unlike the `onAudit` events, the
logger-only events are not all limited to ids. Treat your log
pipeline as holding personal data, or redact `email` in your logger
adapter.

Role changes have no dedicated event. A change made by an operator
while impersonating is captured by `impersonated operation`, and the
plugin's access rules refuse it. To audit every role change by
anyone, add your own `afterChange` hook on the users collection that
compares `previousDoc.roles` with `doc.roles`.

## Delivery semantics

- **Synchronous and in-band.** `onAudit` is called synchronously
  inside the audited code path: Payload's `beforeOperation` hook, the
  organization endpoint handler, or `createSessionFor`. The plugin
  does not buffer, batch, retry or deduplicate. Events arrive in call
  order, once per call.
- **The return value is ignored.** If your sink returns a promise,
  the plugin does not await it, and a rejection becomes an unhandled
  rejection. Start the write, then route its failure somewhere
  (the recipe below uses `.catch(onError)`).
- **A sink that throws is fail-closed.** A synchronous throw
  propagates. Inside `beforeOperation` it fails the operation the
  impersonating operator attempted (proven by the recipe test). In an
  organization endpoint, the refusal turns into an error response
  instead of the 403. In `createSessionFor`, the provider has
  **already stored** the session, but the call throws before
  returning the token, so the session stays orphaned until it expires
  or you revoke it with `revokeAllForUser`. Throw only if you mean
  "no audit, no action". Otherwise catch inside the sink.
- **The logger runs first.** If `logger.info` throws, the sink is not
  called for that event.
- **Cost on the request path.** Every operation performed while
  impersonating calls the sink. Keep the synchronous part cheap: an
  enqueue or a non-awaited insert.

## Recipe: an append-only audit-log collection

Keep the trail in Payload itself. Payload owns the users, so a
Payload collection keeps the audit records in the same database,
backups and access model. The collection is append-only: `create`,
`update` and `delete` are denied to everyone, and the sink writes
through the Local API with `overrideAccess: true`.

Do not pass `req` to the write. Without `req`, the row is written
outside the audited operation's transaction, so a denied or
rolled-back attempt stays recorded. The plugin's audit hook (which
runs on this collection too) then sees no impersonated user, so
writing an audit row never audits itself. If you passed the
impersonated `req`, every write would audit itself again,
indefinitely.

```ts
// lib/audit.ts
import { isRecord, type LoggerPort } from '@payload-auth-link/core'
import type { AuthLinkPluginOptions } from '@payload-auth-link/plugin'
import type { CollectionConfig, Payload } from 'payload'

type AuditSink = NonNullable<AuthLinkPluginOptions['onAudit']>
type AuditEvent = Parameters<AuditSink>[0]

const hasRole = (user: unknown, role: string): boolean =>
  isRecord(user) && Array.isArray(user.roles) && user.roles.includes(role)

/** Append-only audit trail: rows are written only through `overrideAccess`. */
export const auditLogCollection: CollectionConfig = {
  slug: 'audit-log',
  admin: {
    useAsTitle: 'message',
    defaultColumns: ['message', 'operation', 'actorUserId', 'targetUserId', 'createdAt'],
  },
  access: {
    read: ({ req }) => hasRole(req.user, 'admin'),
    create: () => false,
    update: () => false,
    delete: () => false,
  },
  fields: [
    { name: 'message', type: 'text', required: true, index: true },
    { name: 'operation', type: 'text', index: true },
    { name: 'actorUserId', type: 'text', index: true },
    { name: 'targetUserId', type: 'text', index: true },
    { name: 'fields', type: 'json', required: true },
  ],
}

/**
 * `onAudit` is called synchronously and its return value is ignored,
 * so the write is started here and never awaited by the plugin.
 * Every failure is routed to `onError` (never an unhandled rejection).
 */
export function createPayloadAuditSink(options: {
  readonly payload: () => Promise<Payload>
  readonly onError: (cause: unknown, event: AuditEvent) => void
}): AuditSink {
  return (event) => {
    const text = (key: string): string | undefined => {
      const value = event.fields[key]
      return typeof value === 'string' ? value : undefined
    }
    void options
      .payload()
      .then((payload) =>
        payload.create({
          collection: 'audit-log',
          // No `req`: the row is written outside the audited operation's
          // transaction (a denied or rolled-back attempt stays recorded),
          // and the audit hook on this collection sees no impersonated
          // user, so writing an audit row never audits itself.
          overrideAccess: true,
          data: {
            message: event.message,
            operation: text('operation'),
            actorUserId: text('actorUserId'),
            targetUserId: text('targetUserId') ?? text('userId'),
            fields: { ...event.fields },
          },
        })
      )
      .catch((cause: unknown) => {
        options.onError(cause, event)
      })
  }
}

/**
 * Optional: forward selected logger-only events (see the table in
 * docs/audit.md) to the same sink. Message text is diagnostics, not
 * contract, so pin the set in a test of your own.
 */
export function withDurableMessages(
  logger: LoggerPort,
  sink: AuditSink,
  messages: ReadonlySet<string>
): LoggerPort {
  const forward = (message: string, fields: AuditEvent['fields'] | undefined): void => {
    if (messages.has(message)) {
      sink({ message, fields: fields ?? {} })
    }
  }
  const wrapped: LoggerPort = {
    ...logger,
    info: (message, fields) => {
      logger.info(message, fields)
      forward(message, fields)
    },
    warn: (message, fields) => {
      logger.warn(message, fields)
      forward(message, fields)
    },
    child: () => wrapped,
  }
  return wrapped
}
```

Wire it in `payload.config.ts`. `getPayload` is called lazily, at the
first event, so referring to the config being built is safe:

```ts
import { authLink } from '@payload-auth-link/plugin'
import { buildConfig, getPayload } from 'payload'
import { auditLogCollection, createPayloadAuditSink, withDurableMessages } from './lib/audit'
import { appLogger } from './lib/logger' // your LoggerPort adapter

const auditSink = createPayloadAuditSink({
  payload: () => getPayload({ config }),
  onError: (cause, event) => {
    appLogger.error('audit write failed', { message: event.message, cause })
  },
})

const config = buildConfig({
  // …
  collections: [/* users, … */ auditLogCollection],
  plugins: [
    authLink({
      // …
      onAudit: auditSink,
      // Optional: also persist chosen logger-only events.
      logger: withDurableMessages(
        appLogger,
        auditSink,
        new Set(['impersonated session used', 'session refused: user suspended'])
      ),
    }),
  ],
})

export default config
```

Notes:

- `hasRole(req.user, 'admin')` checks the roles the plugin puts on
  `req.user`: canonical slugs by default, or stored values with
  `projectRolesAs: 'stored'`. Use whatever role your operators hold.
- Adding the collection is a schema change in **your** app. Create
  and commit a migration for it, as with any collection
  ([upgrading.md](upgrading.md#running-production-on-migrations-not-push)).
- Retention is up to you. Nothing prunes `audit-log`. Schedule a job
  that deletes rows older than your retention period, using
  `overrideAccess: true`.
- Do not include the two `onAudit` messages in the
  `withDurableMessages` set. They already reach the sink, and
  including them would write each event twice.

### Shipping to an external store instead

The same shape works for a SIEM or log store. The sink enqueues
synchronously and a background flusher ships the events (an HTTP
batch endpoint, a queue, OpenTelemetry logs). Keep the same rules:
never throw from the sink unless you want fail-closed behavior,
always catch failures of the async part, and keep the flusher's queue
bounded. If the store is unavailable, fall back to the logger rather
than dropping events silently.
