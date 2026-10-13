---
'@payload-auth-link/provider-better-auth': patch
---

Adapter fix: a case-insensitive `eq` (translated to a contains-match
plus an in-memory exact filter) no longer loses rows to pagination.
Previously `findMany` fetched a single `skip + limit` window and
`findOne` a fixed 100-row window, then filtered — decoy rows that
merely contain the search text could fill the window, so real matches
past it vanished (empty findMany pages, false-null findOne) and
offsets counted unfiltered rows.

Now, when a post-filter is in play, both operations page through the
source with a stable sort until `skip + limit` **filtered** rows are
collected (or the source is exhausted), so offsets count filtered
rows and results are complete. Non-filtered queries are unchanged.
Pinned by tests planting 150 contains-match decoys ahead of the real
row (beyond both the page size and the old fixed window).

Upgrade impact: none for the database; queries return complete,
correctly-offset results.
