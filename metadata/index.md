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
| F | 772 | new functionality |
| B | 1566 | bug fix |
| D | 421 | spec/doc edits (no code) |
| R | 87  | revision block on FROZEN spec |
| Z | 19  | freeze a DRAFT spec |
| C | 244 | tooling / deps / CI plumbing |
| P17 | 18 | phase-17 work (tty + login) |

## Reserved (in flight)

`C238` was live in `wt-C238` while this file still read `next = 238`, so the
build-warning sweep took `C239`–`C242` (cfg hygiene / trivial lints / dead-code
triage / host-config dead_code scope) and advanced the counter to 243.

The `C` row itself was LOST on 2026-07-28: a concurrent merge
(`b72bd67e0` "merge origin/main: keep B=1510") resolved the conflict by
duplicating the `B` row over it and dropping a third copy into this section.
Restored here — a lost row silently hands the next lane a colliding number.

`F761`–`F764` reserved 2026-07-27 for the syscall-matrix audit batches
(xattr-at family, sched/ioprio, mempolicy/mseal, admin/misc). Counter already
advanced to 765 so a concurrent lane cannot collide with them.

`D406`-`D409` reserved 2026-07-27 for the Linux subsystem-audit lanes
(mm, sched, vfs/block, net/security). Counter advanced to 410.

`B1505`-`B1507` in flight 2026-07-28 — the file read `1505` while local branches
`B1506-psi-trigger-linux-parse` and `B1507-inotify-mark-destroy` already existed
(their bumps unmerged). `B1508` taken by the fsconfig `SET_FD` lane and the
counter advanced to 1509 so none of the three live lanes collides.

`B1459`-`B1465` reserved 2026-07-27 for the concurrent compliance-blocker
lanes (signal frames, wait deadlines, poll subscribers, durable writes, procfs
creds, exec privilege transition). Counter advanced to 1466.

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
