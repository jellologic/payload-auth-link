---
'@payload-auth-link/plugin': patch
---

One session resolution per request (issue #42): the auth strategy and
the endpoint handler verify the same `req.headers` reference for a
single request, so each refused request walked the providers (and
logged its warnings) three times. Verification results are now
memoized on the headers identity — one provider walk, one set of
logs, one resolution per request; a new request brings new headers
and a fresh verification. The guest read is unchanged.

Upgrade impact: none — refused requests now log each warning once
instead of three times, and refused requests stop paying repeated
provider round-trips.
