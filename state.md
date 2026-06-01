# Session hand-off — 2026-06-01

## TL;DR
Autonomous run, Track K systemd-blockers. This session closed Track K's
**foundation-sound surface**. Last 2 PRs: F319 (#1418), F320 (#1419).

## Done this session (Track K1b enforcement)
- **F319 cgroup.freeze REAL** (#1418): `cgroup.freeze=1` now actually
  freezes member tasks, not just a tree flag. Per-task `Task::frozen`
  AtomicBool gates the single runqueue **enqueue chokepoint**
  (`runqueue.rs`); `freeze_task`/`unfreeze_task` (`live/sigpend.rs`,
  re-exported at `sched::live`); boot-installed `FREEZE_HOOK` mirroring
  cgroup.kill's SIGNAL_HOOK; `cgroup_boot::install_hooks()` (net-zero
  lib.rs). Split `task::cap` consts → `task/cap.rs` (task.rs was >1000).
  Hosted test: enqueue skips frozen, admits thawed.
- **F320 memory.max REAL** (#1419): memory controller charges + enforces.
  Per-pid charge map in cgroup tree (`try_charge_mem`/`uncharge_mem`/
  `subtree_mem`), hierarchical ancestor-cap check, exit uncharges whole
  footprint (symmetric by construction), charge migrates on cgroup move.
  `memory.current`/`memory.stat` now report `subtree_mem` (were static 0).
  Wired at `sys_brk` (grow charges delta → ENOMEM-as-old-brk on cap;
  shrink uncharges). 7 hosted unit tests prove the lot.

## Track K status (TASKS.md K-track)
- K1/K2/K3/K6 + K2V VFS rebuild: done (prior sessions).
- K1b enforcement: **foundation-sound items DONE** — freeze (F319),
  pids-counts-threads (prior), memory.max (F320). Dynamic
  /proc/self/mountinfo cgroup2 line already satisfied (`procfs/mounts.rs`
  reads `vfs::mount::snapshot`; cgroup2 registers via `vfs::mount::register`).

## OPEN DECISION — Track K → L boundary (asked the user)
K1b's remaining items — **cpu.weight/cpu.max, io controller, cpuset
affinity** — are genuinely BLOCKED on a preemptive-SMP scheduler:
- Audit confirms NO per-task runtime accounting: `timer_tick` integration
  is stubbed (`live/preempt.rs` `tick_pick_next` no-op variant;
  `schedule.rs:57` "timer_tick integration will scale by wall_dt/weight
  ... subsequent P1-N"). vruntime updates deferred.
- cpu.max needs per-tick runtime charging + deschedule-on-quota (the freeze
  mechanism gives the deschedule half; the accounting half is missing).
- Building these on the cooperative-with-timer-wake scheduler = bolt-on on
  sand (CLAUDE.md "foundation before wiring"; no v1-subset).
Fork presented to user: (A) build preemptive-SMP scheduler foundation now
(unblocks cpu/io/cgroup enforcement; real phase-4 gap), (B) proceed to
Track L (shared-lib userspace / systemd vendoring — distro path), (C) other.

## First task next session
Act on the user's Track-K→L fork answer. If (B) Track L: audit TASKS.md
L-track + `docs/29a` userspace platform for the systemd/shared-lib
vendoring entry point. If (A) scheduler: real `timer_tick` runtime
accounting (update_curr/delta_exec) as the foundation, then cpu.max via
freeze-on-quota.

## CRITICAL HARNESS RULES (unchanged — read before pushing)
- Boot gate = backgrounded PLAIN `git push` (run_in_background +
  dangerouslyDisableSandbox), pre-push hook boots both arches under KVM.
  `PUSH_DONE rc=0` in `.pushNNN.txt` = passed. If hook fails at
  "make smoke-x86 did not reach login" → CAT-smoke flake, RE-PUSH plain.
- NEVER put literal `qemu-system` in a Bash command — `pkill -f` self-kills
  the wrapper shell.
- `git push 2>FILE`; explicit `git add <paths>` NOT `-A`; valid-hex test
  literals; lib.rs AT 1000-line cap (net-zero edits only).
- After merge: `git checkout main && git pull`, `git checkout --
  kernel/blobs/rootfs-*.img`, rm `.pushNNN.txt`.
- Inner loop = hosted `cargo test -p <crate>` + `cargo test --workspace`;
  `cargo run -p xtask -- spec-lint` clean before every commit AND PR.
- Branch per stage F<NN>- (next: F321); user does NOT want me polling
  GitHub CI ("it slows development; I'll flag problems").
- User wants enforcement PROVABLE via hosted unit tests, not just wired.
