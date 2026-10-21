---
'@payload-auth-link/migrate': patch
---

The legacy key-value sweep (the one-time migration of `payload-auth-link/migrate/*` records out of the app's `payload.config.kv`) now fails with its own named error when the KV refuses the unbounded `keys()` it needs — a large Redis-backed KV does (Upstash: "ERR too many keys to fetch, please use SCAN") — instead of a generic storage error that sent operators chasing Payload migrations (#155). New `--no-legacy-kv` flag on every kit command skips the sweep entirely for apps whose KV never held kit records (anything first seen at 0.13+): the records collection becomes the only store consulted. Nothing else changes; the sweep failure writes nothing.
