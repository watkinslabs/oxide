# Branch-counter index (HISTORY ONLY — no longer authoritative)

**Counters are derived from git, not from this file.** Claim a number with:

    tools/next-branch.sh --claim <TYPE> <kebab-title>

which pushes a `claim/<T><NN>` ref to origin BEFORE returning the name. Two lanes
racing push different values to the same ref and the remote refuses the loser,
which then retries with the next number — the atomicity is the remote's, not a
check-then-act in the script. `tools/next-branch.sh <TYPE>` still just READS the
next number without claiming it; `--dry-run` says so explicitly.

The `next` table that used to live here was a second source of truth for a number
git already knows, and it fell behind on nearly every wave of this project's
parallel lanes — issuing `D399` twice, losing the `C` row to a conflict
resolution, and firing a red `make ci` gate over drift that changed nothing. It is
retired. What stays below is the history: which numbers were reserved, which
collided, and why — because that record is not derivable from git.

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

`B1653`-`B1662`, `C244`-`C246`, `F777` reserved 2026-08-01 for the
known-issues clearing wave (net options, AF_UNIX OOB, TCP defer-accept /
zerocopy-receive, keyring keyctl gaps, drain_loopback backlog, net test-suite
races, gate-set hardening). Counters advanced past them so concurrent lanes
cannot collide.

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
