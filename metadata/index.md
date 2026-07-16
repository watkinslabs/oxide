# Branch-counter index (AUTHORITATIVE)

HARD RULE: branch counters live HERE, not invented. Before creating a branch
of type `<T>` (F/B/D/R/Z/C), read the `next` value below, name the branch
`<T><NN>-<kebab-title>` (zero-padded ≥2 digits, widen past 99→3 digits), then
INCREMENT the value here and commit it (same PR or a tracking commit) so the
next run/branch is correct. Phase branches `P<n>-<NN>` use the per-phase
counter; bump the matching `P<n>` line.

Counters are `next` (the number to USE for the next branch of that type).
Seeded 2026-06-12 from `git log --all` max-per-type + this session's merges.

| Type | next | meaning |
|---|---|---|
| F | 699 | new functionality |
| B | 1139 | bug fix |
| D | 254 | spec/doc edits (no code) |
| R | 84  | revision block on FROZEN spec |
| Z | 19  | freeze a DRAFT spec |
| C | 111 | tooling / deps / CI plumbing |
| P17 | 18 | phase-17 work (tty + login) |
