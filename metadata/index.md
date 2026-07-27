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
| F | 753 | new functionality |
| B | 1453 | bug fix |
| D | 401 | spec/doc edits (no code) |
| R | 84  | revision block on FROZEN spec |
| Z | 19  | freeze a DRAFT spec |
| C | 229 | tooling / deps / CI plumbing |
| P17 | 18 | phase-17 work (tty + login) |

## Known counter collisions

`D399` was issued twice — `D399-handoff-refresh` and
`D399-3a-design-and-admission-gap`. Both merged cleanly under distinct titles;
history is intact and the counter is correct from `D400` onward. Recorded so a
later audit does not read the duplicate as broken counter logic.

Cause: a counter was read from this file and used while a concurrent lane had
already claimed it and not yet merged its bump. The file is only authoritative
for lanes that check for live ones first — `git worktree list`, `git branch -a`
and `gh pr list` before taking a number, per CLAUDE.md "Claim work before
starting". Reading the file alone is not sufficient when another lane is
active.
