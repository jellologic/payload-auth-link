---
'@payload-auth-link/core': minor
'@payload-auth-link/plugin': minor
---

The plugin is audible by default (issue #15): `authLink({ logger })`
now defaults to a **console logger** instead of the silent one, so
session refusals (expired, channel not admitted, suspended,
provider errors, a session-shaped cookie that resolves to nothing)
and the impersonation audit actually land somewhere without
configuration. `nullLogger()` remains the explicit opt-out.

- Core adds `consoleLogger()` (info/warn/error to the matching
  console level, fields as a JSON suffix, debug stays silent) and
  `isSilentLogger()`.
- New `onAudit` option: a durable sink called with every
  impersonation audit event, in addition to the logger — "audited"
  should survive log rotation. With an impersonation-capable
  provider, a silent logger, and no `onAudit`, the plugin warns once
  at startup through the console that audit events are being
  dropped.
- The per-request "verification failed: invalid session" residue
  (every anonymous request) moved to debug level; every actionable
  refusal keeps its warning with reason, provider, and channel.
- README's impersonation row now says what auditing means.

Upgrade impact: default-behaviour change — servers will print
warnings for refused sessions by default. Pass
`logger: nullLogger()` to restore silence; pass `onAudit` to make
the impersonation audit durable.
